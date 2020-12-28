#include <set>
#include <byteswap.h>
#include "solver.h"

namespace qsym {

namespace {

const uint64_t kUsToS = 1000000;
const int kSessionIdLength = 32;
const unsigned kSolverTimeout = 10000; // 10 seconds

std::string toString6digit(INT32 val) {
  char buf[6 + 1]; // ndigit + 1
  snprintf(buf, 7, "%06d", val);
  buf[6] = '\0';
  return std::string(buf);
}

uint64_t getTimeStamp() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec * kUsToS + tv.tv_usec;
}

// 从当前 x > 3 形式的二元分支约束 e 中，提取出 x 到 expr_sym，提取出 3 到 expr_const
void parseConstSym( ExprRef   e, 
		    Kind &    op, 
		    ExprRef & expr_sym, 
		    ExprRef & expr_const
		  ) 
{
  // 因为 e 是 addConstraint 时候的分支约束，所以必然为二元运算表达式
  for (INT32 i = 0; i < 2; i++) {
    expr_sym = e->getChild(i);
    expr_const = e->getChild(1 - i);
    if (!isConstant(expr_sym)
        && isConstant(expr_const)) {
      op = i == 0 ? e->kind() : swapKind(e->kind());
      return;
    }
  }
  UNREACHABLE();
}

void getCanonicalExpr(ExprRef e,
    ExprRef* canonical,
    llvm::APInt* adjustment=NULL) {
  ExprRef first = NULL;
  ExprRef second = NULL;
  // e == Const + Sym --> canonical == Sym
  switch (e->kind()) {
    // TODO: handle Sub
    case Add:
      first = e->getFirstChild();
      second = e->getSecondChild();
      if (isConstant(first)) {
        *canonical = second;
        if (adjustment != NULL)
          *adjustment =
            static_pointer_cast<ConstantExpr>(first)->value();
        return;
      case Sub:
        // C_0 - Sym
        first = e->getFirstChild();
        second = e->getSecondChild();
        // XXX: need to handle reference count
        if (isConstant(first)) {
          *canonical = g_expr_builder->createNeg(second);
          if (adjustment != NULL)
            *adjustment = static_pointer_cast<ConstantExpr>(first)->value();
          return;
        }
      }
    default:
      break;
  }
  if (adjustment != NULL)
    *adjustment = llvm::APInt(e->bits(), 0);
  *canonical = e;
}

inline bool isEqual(ExprRef e, bool taken) {
  return (e->kind() == Equal && taken) ||
    (e->kind() == Distinct && !taken);
}

} // namespace

Solver::Solver(
    const std::string input_file,
    const std::string out_dir,
    const std::string bitmap)
  : input_file_(input_file)
  , inputs_()
  , out_dir_(out_dir)
  , context_(g_z3_context)
  , solver_(z3::solver(context_, "QF_BV"))
  , num_generated_(0)
  , trace_(bitmap)
  , last_interested_(false)
  , syncing_(false)
  , start_time_(getTimeStamp())
  , solving_time_(0)
  , last_pc_(0)
  , dep_forest_()
{
  // Set timeout for solver
  z3::params p(context_);
  p.set(":timeout", kSolverTimeout);
  solver_.set(p);

  checkOutDir();
  readInput();
}

void Solver::push() {
  solver_.push();
}

void Solver::reset() {
  solver_.reset();
}

void Solver::pop() {
  solver_.pop();
}

void Solver::add(z3::expr expr) {
  if (!expr.is_const())
    solver_.add(expr.simplify());
}

z3::check_result Solver::check() {
  uint64_t before = getTimeStamp();
  z3::check_result res;
  LOG_STAT(
      "SMT: { \"solving_time\": " + decstr(solving_time_) + ", "
      + "\"total_time\": " + decstr(before - start_time_) + " }\n");
  // LOG_DEBUG("Constraints: " + solver_.to_smt2() + "\n");
  try {
    res = solver_.check();
  }
  catch(z3::exception e) {
    // https://github.com/Z3Prover/z3/issues/419
    // timeout can cause exception
    res = z3::unknown;
  }
  uint64_t cur = getTimeStamp();
  uint64_t elapsed = cur - before;
  solving_time_ += elapsed;
  LOG_STAT("SMT: { \"solving_time\": " + decstr(solving_time_) + " }\n");
  return res;
}

bool Solver::checkAndSave(const std::string& postfix) {
  if (check() == z3::sat) {
    saveValues(postfix);
    return true;
  }
  else {
    LOG_DEBUG("unsat\n");
    return false;
  }
}

void Solver::addJcc(ExprRef e, bool taken, ADDRINT pc) {
  // Save the last instruction pointer for debugging
  last_pc_ = pc;

  if (e->isConcrete())
    return;

  // if e == Bool(true), then ignore
  if (e->kind() == Bool) {
    assert(!(castAs<BoolExpr>(e)->value()  ^ taken));
    return;
  }

  assert(isRelational(e.get()));

  // check duplication before really solving something,
  // some can be handled by range based constraint solving
  bool is_interesting;
  if (pc == 0) {
    // If addJcc() is called by special case, then rely on last_interested_
    is_interesting = last_interested_;
  }
  else
    is_interesting = isInterestingJcc(e, taken, pc);

  if (is_interesting)
    negatePath(e, taken);
  addConstraint(e, taken, is_interesting);
}

void Solver::addAddr(ExprRef e, ADDRINT addr) {
  llvm::APInt v(e->bits(), addr);
  addAddr(e, v);
}

void Solver::addAddr(ExprRef e, llvm::APInt addr) {
  if (e->isConcrete())
    return;

  if (last_interested_) {
    reset();
    // TODO: add optimize in z3
    syncConstraints(e);
    if (check() != z3::sat)
      return;
    z3::expr &z3_expr = e->toZ3Expr();

    // TODO: add unbound case
    z3::expr min_expr = getMinValue(z3_expr);
    z3::expr max_expr = getMaxValue(z3_expr);
    solveOne(z3_expr == min_expr);
    solveOne(z3_expr == max_expr);
  }

  addValue(e, addr);
}

void Solver::addValue(ExprRef e, ADDRINT val) {
  llvm::APInt v(e->bits(), val);
  addValue(e, v);
}

void Solver::addValue(ExprRef e, llvm::APInt val) {
  if (e->isConcrete())
    return;

#ifdef CONFIG_TRACE
  trace_addValue(e, val);
#endif

  ExprRef expr_val = g_expr_builder->createConstant(val, e->bits());
  ExprRef expr_concrete = g_expr_builder->createBinaryExpr(Equal, e, expr_val);

  addConstraint(expr_concrete, true, false);
}

void Solver::solveAll(ExprRef e, llvm::APInt val) {
  if (last_interested_) {
    std::string postfix = "";
    ExprRef expr_val = g_expr_builder->createConstant(val, e->bits());
    ExprRef expr_concrete = g_expr_builder->createBinaryExpr(Equal, e, expr_val);

    reset();
    syncConstraints(e);
    addToSolver(expr_concrete, false);

    if (check() != z3::sat) {
      // Optimistic solving
      reset();
      addToSolver(expr_concrete, false);
      postfix = "optimistic";
    }

    z3::expr z3_expr = e->toZ3Expr();
    while(true) {
      if (!checkAndSave(postfix))
        break;
      z3::expr value = getPossibleValue(z3_expr);
      add(value != z3_expr);
    }
  }
  addValue(e, val);
}

UINT8 Solver::getInput(ADDRINT index) {
  assert(index < inputs_.size());
  return inputs_[index];
}

void Solver::checkOutDir() {
  // skip if there is no out_dir
  if (out_dir_.empty()) {
    LOG_INFO("Since output directory is not set, use stdout\n");
    return;
  }

  struct stat info;
  if (stat(out_dir_.c_str(), &info) != 0
      || !(info.st_mode & S_IFDIR)) {
    LOG_FATAL("No such directory\n");
    exit(-1);
  }
}

void Solver::readInput() {
  std::ifstream ifs (input_file_, std::ifstream::in | std::ifstream::binary);
  if (ifs.fail()) {
    LOG_FATAL("Cannot open an input file\n");
    exit(-1);
  }

  char ch;
  while (ifs.get(ch))
    inputs_.push_back((UINT8)ch);
}

std::vector<UINT8> Solver::getConcreteValues() {
  // TODO: change from real input
  z3::model m = solver_.get_model();
  unsigned num_constants = m.num_consts();
  std::vector<UINT8> values = inputs_;
  for (unsigned i = 0; i < num_constants; i++) {
    z3::func_decl decl = m.get_const_decl(i);
    z3::expr e = m.get_const_interp(decl);
    z3::symbol name = decl.name();

    if (name.kind() == Z3_INT_SYMBOL) {
      int value = e.get_numeral_int();
      values[name.to_int()] = (UINT8)value;
    }
  }
  return values;
}

void Solver::saveValues(const std::string& postfix) {
  std::vector<UINT8> values = getConcreteValues();

  // If no output directory is specified, then just print it out
  if (out_dir_.empty()) {
    printValues(values);
    return;
  }

  std::string fname = out_dir_+ "/" + toString6digit(num_generated_);
  // Add postfix to record where it is genereated
  if (!postfix.empty())
      fname = fname + "-" + postfix;
  ofstream of(fname, std::ofstream::out | std::ofstream::binary);
  LOG_INFO("New testcase: " + fname + "\n");
  if (of.fail())
    LOG_FATAL("Unable to open a file to write results\n");

      // TODO: batch write
      for (unsigned i = 0; i < values.size(); i++) {
        char val = values[i];
        of.write(&val, sizeof(val));
      }

  of.close();
  num_generated_++;
}

void Solver::printValues(const std::vector<UINT8>& values) {
  fprintf(stderr, "[INFO] Values: ");
  for (unsigned i = 0; i < values.size(); i++) {
    fprintf(stderr, "\\x%02X", values[i]);
  }
  fprintf(stderr, "\n");
}

z3::expr Solver::getPossibleValue(z3::expr& z3_expr) {
  z3::model m = solver_.get_model();
  return m.eval(z3_expr);
}

z3::expr Solver::getMinValue(z3::expr& z3_expr) {
  push();
  z3::expr value(context_);
  while (true) {
    if (checkAndSave()) {
      value = getPossibleValue(z3_expr);
      solver_.add(z3::ult(z3_expr, value));
    }
    else
      break;
  }
  pop();
  return value;
}

z3::expr Solver::getMaxValue(z3::expr& z3_expr) {
  push();
  z3::expr value(context_);
  while (true) {
    if (checkAndSave()) {
      value = getPossibleValue(z3_expr);
      solver_.add(z3::ugt(z3_expr, value));
    }
    else
      break;
  }
  pop();
  return value;
}

void Solver::addToSolver(ExprRef e, bool taken) {
  e->simplify();
  if (!taken)
    e = g_expr_builder->createLNot(e);
  add(e->toZ3Expr());
}

void Solver::syncConstraints(ExprRef e) {
  std::set<std::shared_ptr<DependencyTree<Expr>>> forest;

  // 得到 e 所依赖的所有外部输入字节的偏移号
  DependencySet* deps = e->getDependencies();

  // 得到 “e 所依赖的各个外部输入字节号” 所相关的所有 Expr : 每个外部输入字节，都对应有一个 DependencyTree<Expr> 
  for (const size_t& index : *deps)
    forest.insert(dep_forest_.find(index));

  for (std::shared_ptr<DependencyTree<Expr>> tree : forest) {
    std::vector<std::shared_ptr<Expr>> nodes = tree->getNodes();
    for (std::shared_ptr<Expr> node : nodes) {
      // 这是一个关系型的 Expr
      if (isRelational(node.get()))
        addToSolver(node, true);
      else 
      {
        // Process range-based constraints
        bool valid = false;
        for (INT32 i = 0; i < 2; i++) {
          ExprRef expr_range = getRangeConstraint(node, i);
          if (expr_range != NULL) {
            addToSolver(expr_range, true);
            valid = true;
          }
        }

        // One of range expressions should be non-NULL
        if (!valid)
          LOG_INFO(std::string(__func__) + ": Incorrect constraints are inserted\n");
      }
    }
  }

  checkFeasible();
}

void Solver::addConstraint(ExprRef e, bool taken, bool is_interesting) {
  if (auto NE = castAs<LNotExpr>(e)) {
    // 这里的 expr() 函数实质为 getFirstChild()
    addConstraint(NE->expr(), !taken, is_interesting);
    return;
  }
  if (!addRangeConstraint(e, taken))
    addNormalConstraint(e, taken);
}

void Solver::addConstraint(ExprRef e) {
  // If e is true, then just skip
  if (e->kind() == Bool) {
    QSYM_ASSERT(castAs<BoolExpr>(e)->value());
    return;
  }
  if (e->isConcrete())
    return;
  dep_forest_.addNode(e);
}

bool Solver::addRangeConstraint(ExprRef e, bool taken) {
  if (!isConstSym(e))
    return false;

  Kind kind = Invalid;
  ExprRef expr_sym, expr_const;

  // 从当前 x > 3 形式的二元分支约束 e 中，提取出 x 到 expr_sym，提取出 3 到 expr_const
  parseConstSym( e, 
		 kind,      // out
		 expr_sym,  // out
		 expr_const // out
	       );
  ExprRef canonical = NULL;
  llvm::APInt adjustment;

  // 如果 expr_sym 形如 x + 3, 3 - x 之类，则将 x 提取到 canonical，而 3 放入 adjustment
  getCanonicalExpr(expr_sym, &canonical, &adjustment);
  llvm::APInt value = static_pointer_cast<ConstantExpr>(expr_const)->value();

  if (!taken)
    kind = negateKind(kind);

  canonical->addConstraint( kind, 
		            value, // 约束右端的常量
                            adjustment
			  );
  addConstraint(canonical);
  //updated_exprs_.insert(canonical);
  return true;
}

void Solver::addNormalConstraint(ExprRef e, bool taken) {
  if (!taken)
    e = g_expr_builder->createLNot(e);
  addConstraint(e);
}

ExprRef Solver::getRangeConstraint(ExprRef e, bool is_unsigned) {
  Kind lower_kind = is_unsigned ? Uge : Sge;
  Kind upper_kind = is_unsigned ? Ule : Sle;
  RangeSet *rs = e->getRangeSet(is_unsigned);
  if (rs == NULL)
    return NULL;

  ExprRef expr = NULL;
  for ( auto i = rs->begin(), end = rs->end();
        i != end; 
	i++
      ) 
  {
    const llvm::APSInt& from = i->From();
    const llvm::APSInt& to = i->To();
    ExprRef bound = NULL;

    if (from == to) {
      // can simplify this case
      ExprRef imm = g_expr_builder->createConstant(from, e->bits());
      bound = g_expr_builder->createEqual(e, imm);
    }
    else
    {
      ExprRef lb_imm = g_expr_builder->createConstant(i->From(), e->bits());
      ExprRef ub_imm = g_expr_builder->createConstant(i->To(), e->bits());
      ExprRef lb = g_expr_builder->createBinaryExpr(lower_kind, e, lb_imm);
      ExprRef ub = g_expr_builder->createBinaryExpr(upper_kind, e, ub_imm);
      bound = g_expr_builder->createLAnd(lb, ub);
    }

    if (expr == NULL)
      expr = bound;
    else
      expr = g_expr_builder->createLOr(expr, bound);
  }

  return expr;
}


bool Solver::isInterestingJcc(ExprRef rel_expr, bool taken, ADDRINT pc) {
  bool interesting = trace_.isInterestingBranch(pc, taken);
  // record for other decision
  last_interested_ = interesting;
  return interesting;
}

void Solver::negatePath(ExprRef e, bool taken) {
  // 这里的 reset() 将之前 z3 solver 的求解上下文都清除了 (删除所有的 assertions)，
  // 意味着此时的可满足性求解仅仅关注于当前分支约束，而不对之前的路径约束进行考虑
  reset();

  // XXX: 这里可能是将和 e 相关的约束同步进来
  syncConstraints(e);

  // 将当前未取的分支约束加入 solver 上下文中
  addToSolver(e, !taken);
  bool sat = checkAndSave();
  if (!sat) {
    reset();
    // optimistic solving
    addToSolver(e, !taken);
    checkAndSave("optimistic");
  }
}

void Solver::solveOne(z3::expr z3_expr) {
  push();
  add(z3_expr);
  checkAndSave();
  pop();
}

void Solver::checkFeasible() {
#ifdef CONFIG_TRACE
  if (check() == z3::unsat)
    LOG_FATAL("Infeasible constraints: " + solver_.to_smt2() + "\n");
#endif
}

} // namespace qsym

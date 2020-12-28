#ifndef QSYM_DEPENDENCY_H_
#define QSYM_DEPENDENCY_H_

#include <iostream>
#include <memory>
#include <set>
#include <vector>

namespace qsym {

  typedef std::set<size_t> DependencySet;

  class DependencyNode {
    public:
      DependencyNode();
      virtual ~DependencyNode();
      DependencySet* getDependencies();
      virtual DependencySet computeDependencies() = 0;

    private:
      DependencySet* dependencies_;
  };

  template<class T>
  class DependencyTree {
    public:
      void addNode(std::shared_ptr<T> node) {
        DependencySet* deps = node->getDependencies();
        nodes_.push_back(node);
        deps_.insert(deps->begin(), deps->end());
      }

      void merge(const DependencyTree<T>& other) {
        const DependencySet& other_deps = other.getDependencies();
        const std::vector<std::shared_ptr<T>>& other_nodes = other.getNodes();

        nodes_.insert(nodes_.end(), other_nodes.begin(), other_nodes.end());
        deps_.insert(other_deps.begin(), other_deps.end());
      }

      const DependencySet & getDependencies() const {
        return deps_;
      }

      const std::vector<std::shared_ptr<T>>& getNodes() const {
        return nodes_;
      }

    private:
      std::vector<std::shared_ptr<T>> nodes_;
      DependencySet deps_;
  };

  template<class T>
  class DependencyForest {
    public:
      std::shared_ptr<DependencyTree<T>> find(size_t index) {
        if (forest_.size() <= index)
          forest_.resize(index + 1);

        if (forest_[index] == NULL)
          forest_[index] = std::make_shared<DependencyTree<T>>();

        assert(forest_[index] != NULL);
        return forest_[index];
      }

      // 对于给定的 node (Expr 类型)，依据其所依赖的外部输入字节偏移号，将	
      void addNode(std::shared_ptr<T> node) {
        DependencySet* deps = node->getDependencies();
        std::shared_ptr<DependencyTree<T>> tree = NULL;
        for (const size_t& index : *deps) {
          std::shared_ptr<DependencyTree<T>> other_tree = find(index);
          if (tree == NULL)
            tree = other_tree;
          else if (tree != other_tree) {
            tree->merge(*other_tree);
            // Update existing reference
            for (const size_t& index : other_tree->getDependencies())
              forest_[index] = tree;
          }
          forest_[index] = tree;
        }
        tree->addNode(node);
      }

    private:
      // 本向量的第 i 个索引位置，对应于“会依赖于偏移 i 位置的输入字节的所有 Expr”
      std::vector<std::shared_ptr<DependencyTree<T>>> forest_;
  };

} // namespace qsym

#endif

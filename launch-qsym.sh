#!/bin/sh

#echo "hello qsym !"

bin/run_qsym_afl.py -a Master-Fuzz -o /DSymFuzzer/output-dir/FuzzExplorer -n qsym -- /DSymFuzzer/fuzz-qsym/bin-dyn-11 @@


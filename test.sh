#!/bin/sh

/2TB-ext4-data/Experiments/DSymFuzzer/fuzz-qsym/venv/lib/python2.7/site-packages/qsym/../../../../third_party/pin-2.14-71313-gcc.4.4.7-linux/pin.sh -ifeellucky -t /2TB-ext4-data/Experiments/DSymFuzzer/fuzz-qsym/venv/lib/python2.7/site-packages/qsym/pintool/obj-ia32/libqsym.so -logfile /home/hhui/t0/qsym-out-2/pin.log -i /home/hhui/Experiments/DSymFuzzer/seed-dir/a0  -o /home/hhui/t0/qsym-out-2 -b  '' -- /home/hhui/Experiments/DSymFuzzer/test-programs/bin-dyn-11

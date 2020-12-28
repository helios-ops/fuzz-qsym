#!/bin/sh

#echo "hello qsym !"

bin/run_qsym_afl.py -a AFLMASTER -o OUT_WORKDIR -n qsym -- QSYM_EXENAME QSYM_CMDLINE


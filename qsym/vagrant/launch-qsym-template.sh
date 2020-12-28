#!/bin/sh

#echo "hello qsym !"

. venv/bin/activate
/home/vagrant/qsym/bin/run_qsym_afl.py -a AFLMASTER -o OUT_WORKDIR -n qsym -v /vagrant/running-aflPath -- QSYM_EXENAME QSYM_CMDLINE


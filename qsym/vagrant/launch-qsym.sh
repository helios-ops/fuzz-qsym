#!/bin/sh

#echo "hello qsym !"

. venv/bin/activate
/home/vagrant/qsym/bin/run_qsym_afl.py -a Master-Fuzz -o /DSymFuzzer/output-dir/FuzzExplorer -n qsym -v /vagrant/running-aflPath -- /vagrant/uaf-01-x86_64 @@


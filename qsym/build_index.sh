#!/bin/sh
rm ./cscope.out
rm ./tags

ctags -R .
cscope -R 

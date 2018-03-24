#!/bin/sh
export LD_LIBRARY_PATH=/usr/local/lib
#cd ./MyPython
exec python vol.py -l vmi://centos6.5x64 --profile=Linuxcentos65x64 linux_memory_analyze

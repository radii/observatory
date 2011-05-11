#!/bin/sh
if [ $# -gt 1 ] ; then
  for resFile in $* ; do python ConvertStreamToPem.py ${resFile} ; done
else
  for resFile in *.results ; do python ConvertStreamToPem.py ${resFile} ; done
fi

#!/usr/bin/env python
import time
import glob
from os import stat

def is_running():
  "Check to see if a scan is running in this directory"
  for dir in glob.glob("/proc/[0-9]*"):
    try:
      # for each running process
      if stat(dir + "/cwd") == stat("."):
        # if it's running in this scan directory
        if stat(dir + "/exe") == stat("/usr/bin/python"):
          # and it's python
          cmdline = open(dir + "/cmdline").read()
          if "ControlScript" in cmdline or "cs2" in cmdline:
            # and it's the control script
            return True
    except:
      pass

  return False
        

fn = glob.glob("Status-*")
assert len(fn) == 1
status = open(fn[0]).readlines()

# this file looks like:

# starting position: 0 Sat Mar 27 23:25:06 2010 (214, '*', '*', 19)
# NMap Completed 0
# certGrab completed 0 Sun Mar 28 01:09:38 2010
# starting position: 1 Sun Mar 28 01:09:38 2010 (214, '*', '*', 148)
# NMap Completed 1
# certGrab completed 1 Sun Mar 28 02:49:36 2010

line = status[0].split() 
startunit = int(line[2])
starttime = time.strptime(" ".join(line[3:8]))

line = status[-1]
try:
  while "certGrab" not in line:
    status = status[:-1]
    line = status[-1]
except:
  print "Haven't completed any work units in this run yet..."
  import sys
  sys.exit(0)

line = line.split()
endunit = int(line[2])
endtime = time.strptime(" ".join(line[3:8]))

lsline = status[-1]
while "starting" not in lsline:
  status = status[:-1]
  lsline = status[-1]

lsline = lsline.split()
laststart = time.strptime(" ".join(lsline[3:8]))

seconds_per_day = 3600 * 24.0
tdelta = time.mktime(endtime) - time.mktime(starttime)
units = float(endunit -startunit)
units_per_second = units / tdelta
units_per_day = units_per_second * seconds_per_day

lunit_per_day = seconds_per_day / (time.mktime(endtime) - time.mktime(laststart))

if is_running():
  print "%.2f units per day (last unit @ %.2f / day)" % (units_per_day, lunit_per_day)
else:
  print "%d units in last run (no longer active)" % units
  if endunit == 4095:
    print "(Ended at 4095)"

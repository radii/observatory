#!/usr/bin/env python
import os, time, random, os.path

MYHOST = 0
STARTPOS = 0 # First position to start scanning at, between 0 and POS_PER_PORTION.
PORTIONS = 12

# overwrite STARTPOS for obscure svn-deployment-related reasons
try: STARTPOS = int(open("startpos").read())
except: pass
try: PORTIONS = int(open("portions").read())
except: pass
try: MYHOST = int(open("myhost").read())
except: pass

# defines the actual ranges we use, i.e. octet 1 starts at 214 ends at 97
# octet 4 starts at 19, ends at 37
myRand = random.Random(0x153C)

def firstOctet():
  bad = [0, 1, 5, 6, 7, 10, 14, 23, 27, 31, 36, 37, 39, 42, 49, 50, 55, 100, 101, 102, 103, 104, 105, 106, 107, 127, 176, 177, 179, 181, 185, 223] + range(224, 256)# ... everything above 223 is bad.
  res = range(0, 256)
  for x in bad:
    res.remove(x)
  myRand.shuffle(res)
  return res

def lastOctet():
  res = range(0, 256)
  myRand.shuffle(res)
  return res

# define the actual ranges used, done once so we don't reuse that RNG
# ranges = [firstOctet(), "*", "*", lastOctet()]

def getTargetAddress(hostNumber, pos):
  assert pos < POS_PER_PORTION , "Count too high"    
  assert hostNumber < PORTIONS, "hostNumber too high"
  o1index = (hostNumber * O1_PER_PORTION) + pos/256
  o4index = pos % 256
  if o4index > 10:
    if not os.path.isdir(`o1[o1index]` + ".x.x.x"):
      # if we've scanned ten targets in this /8, and found no certs, chances
      # are that we aren't going to find any...
      return None
  return (o1[o1index], "*", "*", o4[o4index])

def runNmap(address):
  extras = ""
  if address[0] == 192:
    extras = "--exclude 192.168.*.*,192.0.2.*,192.88.99.*"
  elif address[0] == 172:
    extras = "--exclude 172.16.0.0/12"
  elif address[0] ==198:
    extras = "--exclude 198.18.0.0/15"
  elif address[0] == 169:
    extras = "--exclude 169.254.*.*"
  elif address[0] == 130 and address[3] == 84:
    # linux9.ikp.physik.tu-darmstadt.de
    # we received a request to have this machine blocked from scanning
    extras = "--exclude 130.83.133.84"
  command = "nmap -sS -p443 -n -T4 --min-hostgroup 8192 --open -PN %s -oG range-%d-X-X-%d.txt --max-rtt-timeout 500 %d.*.*.%d > nmap-out-%d-X-X-%d.txt " % (extras, address[0], address[3], address[0], address[3], address[0], address[3])
  os.system(command)
  pass

def grabCerts(address):
  command = "python NMapOutputToList.py range-%d-X-X-%d.txt" % (address[0], address[3])
  os.system(command) #

#
# The following test code demonstrates that the control script cleanly walks
# the IPV4 address space. Ommiting all the "bad" class A networks.
#
#
# test = set()
# for host in xrange(0, 6):
#   for pos in xrange(0, 8192):
#     test.add(getNextAddr(host, pos))
#
# if len(test) != 6 * 8192:
#   print "Test failed! number of unique tuples != number expected!"
# else:
#   print "Test succeeded, range generation looks correct"

def main():
  global o1,o4,POS_PER_PORTION,O1_PER_PORTION
  o1 = firstOctet()
  o4 = lastOctet()
  POS_PER_PORTION = (len(o1) * len(o4)) / PORTIONS
  O1_PER_PORTION = len(o1) / PORTIONS

  print "HostID: %d start position: %d at: %s" % (MYHOST, STARTPOS, time.asctime())
  output = open ('Status-%d.txt' %MYHOST, 'w')

  for pos in xrange(STARTPOS, POS_PER_PORTION):
    cur = getTargetAddress(MYHOST, pos)
    if cur:
      output.write("starting position: %d %s %r\n" %( pos, time.asctime(), cur))
      output.flush()
      runNmap(cur)
      output.write("NMap Completed %d\n" % pos)
      output.flush()
      grabCerts(cur)
      output.write("certGrab completed %d %s\n" % (pos, time.asctime()))
      output.flush()
    else:
      output.write("skipping position: %d %s\n" % (pos, time.asctime()))
      output.flush()


if __name__ == "__main__":
  main()



import os, sys

"""Called by control script, passed in the grepable nmap results, which it 
crudely hacks into a file called IPList, and sends over to the cert grabber."""

def getOpen(filename):
  res = []
  f = open(filename, 'r')
  for line in f.readlines():
    if "open" in line:
      res.append(line[line.find(" ") + 1: line.rfind("(") -1])
  return res

if __name__ == "__main__":
  if len(sys.argv) < 2:
    print "takes nmap greppable output format file name as an arg, runs FasterCertificateGrabber on all the IPs"
  else:
    l = getOpen(sys.argv[1])
    #print "Got: %d IPs" % len(l)
    f = open('IPList-' + sys.argv[1], 'w+')
    for x in l:
      f.write(x + "\n")
    f.close()
    ret = os.system("python FasterCertificateGrabber.py -f IPList-" + sys.argv[1])
    if ret != 0:
      print "Certificate grabber died on", sys.argv[1]

  

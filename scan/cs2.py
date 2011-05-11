# ControlScript used a set of allocated /8s from the nmap source code.  That
# was slightly out of date, and will become moreso.  This one parses IANA's
# list of allocated space and scans the things that have been allocated since
# the age of our first list.

# These were the /8s we skipped in the first pass
bad = [0, 1, 5, 6, 7, 10, 14, 23, 27, 31, 36, 37, 39, 42, 49, 50, 55, 100, 101, 102, 103, 104, 105, 106, 107, 127, 176, 177, 179, 181, 185, 223] + range(224, 256)# ... everything above 223 is bad.

# Conceptually, the cs2 scan ranges over 12, 13, 14, 15 
MYHOST = 12

MYHOST -= 12 # remap these numbers so that they start at 0

from xml.parsers.expat import ParserCreate

parser = ParserCreate()

slash8s = []
prefix = False
status = False


def start_element(name, attrs):
    global prefix,status,new
    if name == "record":
      new = []
    elif name == "prefix":
      prefix = True
    elif name == "status":
      status = True

def end_element(name):
    global prefix,status,new
    if name == "prefix":
      prefix = False
    elif name == "status":
      status = False

def char_data(data):
    global prefix,status,new
    if prefix:
      range,_,mask = data.partition("/")
      print "got", range, mask
      if mask == "8":
        new.append(int(range))
    elif status and new:
      if data in ["ALLOCATED", "LEGACY"]:
        if new[0] in bad:
          print data
          slash8s.extend(new)


parser.StartElementHandler = start_element
parser.EndElementHandler = end_element
parser.CharacterDataHandler = char_data

parser.ParseFile(open("ipv4-address-space.xml"))
print slash8s
import ControlScript
# overwrite the Control script's targets
# Only do 12 of the 13, in order to make the ControlScript's arithmetic happy.
ControlScript.firstOctet = lambda : slash8s[:12]
print "Not scanning ", slash8s[12:], "yet"
ControlScript.PORTIONS = 4
ControlScript.MYHOST=MYHOST
ControlScript.main()

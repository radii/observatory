#!/usr/bin/env python
import MySQLdb
import os, re, sys, urllib
sys.path.append("..")
from dbconnect import dbconnect
db,dbc = dbconnect()
FOUND = "found"

try: 
  os.mkdir(FOUND)
except:
  pass

q = "SELECT DISTINCT `X509v3 extensions:Authority Information Access:CA Issuers - URI` FROM all_certs"
dbc.execute(q)

results = dbc.fetchall()
uris = set()
result = {}
bad = []
good = []
for (tofind,) in results:
  if not tofind:
    continue
  for each in tofind.split(" ANDALSO "):
    uris.add(each)

http_pattern = re.compile("^http:")
for u in uris:
  if http_pattern.match(u):
    print "running", u
    try: 
      result[u] = urllib.urlopen(u).read()
    except:
      bad.append(u)
    good.append(u)
print result
print "%d good and %d bad urls" %(len(good), len(bad))
for n, value in enumerate(result.values()):
  open(FOUND + os.sep + str(n)+".crt", 'wb').write(value)



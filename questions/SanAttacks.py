#!/usr/bin/env python
import MySQLdb
import getopt, pdb, re, sys


akid = "`X509v3 extensions:X509v3 Authority Key Identifier:keyid`"
skid = "`X509v3 extensions:X509v3 Subject Key Identifier`"
ca = "`X509v3 extensions:X509v3 Basic Constraints:CA`"

sys.path.append("..")
from dbconnect import dbconnect
readb,rdbc = dbconnect()

DEBUG=False

try:
  opts, args = getopt.getopt(sys.argv[1:], "",[])
  #for o, a in opts:
  #  if o == '-a':
  #    TABLE = ' all_certs '
  #  elif o == '-o':
  #    TOFIND = a
  #    only_interesting = True
except getopt.GetoptError, err:
  print err
  sys.exit(1)

def sel(q, params = None, MAX = 10000):
 if DEBUG: print q, params
 rdbc.execute(q, params)
 return rdbc.fetchmany(MAX)

COUNTRY_RE = re.compile("(^|\s)C=([a-zA-Z]{1,3})")
ORG_RE = re.compile("(^|\s)O=(.*?)(,?\s?\S*=|$)")

def getOrgs(sub):
  r = []
  for x in ORG_RE.finditer(sub):
    r.append(x.group(2))
  return r

def getCountries(sub):
  r = []
  for x in COUNTRY_RE.finditer(sub):
    r.append(x.group(2))
  return r


def findSignedSubordinates(subject, skid, seen = [], recurse = True):
  q = "select certid, subject, issuer, "\
     +"`X509v3 extensions:X509v3 Subject Key Identifier` from "\
     +TABLE+"where issuer = %s "\
     +"and locate('true', `X509v3 extensions:X509v3 Basic Constraints:CA`) "\
     +"and `X509v3 extensions:X509v3 Authority Key Identifier:keyid` " 
  p = (subject,)
  if skid:
    q += "= %s;"
    p = (subject, skid)
  else:
    q += "is null;"
  r = sel(q, p)
  res = []
  todo = []
  for certid, subject, issuer, skid in r:
    if not certid in seen:
      seen.append(certid)
      if recurse: todo.append((subject, skid))
      res.append((certid, subject, issuer, skid))
  for sub, kid in todo:
    res.extend(findSignedSubordinates(sub, kid, seen))
  return res

def main():
  q = "select certid, count(*) as c from all_certs join anames where not locate('true', `X509v3 extensions:X509v3 Basic Constraints:CA`) and locate('self-signed: OK', moz_valid) and locate (%s, name) group by certid having c > %s;"
  #q = "select certid, name from all_certs join anames where locate('self-signed: OK', moz_valid) and locate ('\.', name);"
  p = ('\.com', 5)
  p = ('\.gov', 1)
  p = ('*\.', 3)
   
  r = sel(q, p)
  t = [(certid, c) for certid, c in r]
  for certid, c in t:
    print "%4d - %d" %(c, certid)
  pdb.set_trace();

if __name__ == "__main__":
  main()

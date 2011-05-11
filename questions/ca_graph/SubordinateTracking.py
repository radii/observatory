#!/usr/bin/env python
import MySQLdb
import getopt, pdb, re, sys


TABLE = ' valid_certs '
TOFIND = 'OU=FBCA'

akid = "`X509v3 extensions:X509v3 Authority Key Identifier:keyid`"
skid = "`X509v3 extensions:X509v3 Subject Key Identifier`"
ca = "`X509v3 extensions:X509v3 Basic Constraints:CA`"

import sys
sys.path.append("..")
from dbconnect import dbconnect
readb,rdbc = dbconnect()

DEBUG=False

try:
  opts, args = getopt.getopt(sys.argv[1:], "ao:",[])
  for o, a in opts:
    if o == '-a':
      TABLE = ' all_certs '
    elif o == '-o':
      TOFIND = a
  #    only_interesting = True

except getopt.GetoptError, err:
  print err
  print "-a use all certs rather than valid_certs. This will include"\
        +" certs that are expired or otherwise invalid."
  print "-o thing to search for in name, override the value "\
        +"that must be located in the subject for the roots."
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

def findSignedLeaves(subject, skid):
  q = "select certid,subject from"+TABLE+"where issuer=%s and (not locate('true',"\
     +"`X509v3 extensions:X509v3 Basic Constraints:CA`) or "\
     +"`X509v3 extensions:X509v3 Basic Constraints:CA` is null) "\
     +"and `X509v3 extensions:X509v3 Authority Key Identifier:keyid` "
  p = (subject,)
  if skid:
    q += "=%s;"
    p = (subject,skid)
  else:
    q += "is null;"
 
  r = sel(q, p)
  return r 

def countSignedLeaves(subject, skid):
  q = "select count(*) from"+TABLE+"where issuer=%s and (not locate('true',"\
     +"`X509v3 extensions:X509v3 Basic Constraints:CA`) or "\
     +"`X509v3 extensions:X509v3 Basic Constraints:CA` is null) "\
     +"and `X509v3 extensions:X509v3 Authority Key Identifier:keyid` "
  p = (subject,)
  if skid:
    q += "=%s;"
    p = (subject,skid)
  else:
    q += "is null;"
 
  r = sel(q, p)
  return r[0][0]


def findSigned(subject, skid):
  return ((findSignedSubordinates(subject,skid), findSignedLeaves(subject, skid)))

def main():
  # find the interesting subjects - consider making this command line, but for now
  q = "select certid, subject, `X509v3 extensions:X509v3 Subject Key Identifier`, "\
     +"startdate, enddate from"+TABLE+"where locate(%s, subject);"

  r = sel(q, (TOFIND,))
  t = [(certid, subject, skid, s, e) for certid, subject, skid, s, e in r]
  all_subs = []
  for certid, subject, skid, s, e in t:
    print "For root certid: %s sub: %s skid: %s start: %s end: %s" % (certid, subject, skid, s, e)
    subCAs = findSignedSubordinates(subject,skid,[certid])
    print len(subCAs)
    all_subs.extend(subCAs)
    for certid, subject, issuer, skid in subCAs:
       print " signed SUB CA certid: %d subject: %s" %(certid, subject)

  for certid, subject, issuer, skid in all_subs:
    print "Subordinate CA certid: %s sub: %s signed these leaves:" % (certid, subject)
    for certid, subject in findSignedLeaves(subject, skid):
      print "\tcertid: %7d sub: %s" % (certid, subject)

if __name__ == "__main__":
  main()

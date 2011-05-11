#!/usr/bin/env python
import MySQLdb
import getopt, pdb, re, sys


akid = "`X509v3 extensions:X509v3 Authority Key Identifier:keyid`"
skid = "`X509v3 extensions:X509v3 Subject Key Identifier`"
ca = "`X509v3 extensions:X509v3 Basic Constraints:CA`"

# db init

import sys
sys.path.append("..")
from dbconnect import dbconnect
readdb,rdbc = dbconnect()

full_issuer_name = False
only_interesting = False

try:
  opts, args = getopt.getopt(sys.argv[1:], "fq",[])
  
  for o, a in opts:
    if o == '-f':
      full_issuer_name = True 
    elif o == '-q':
      only_interesting = True

except getopt.GetoptError, err:
  print err
  print "-f full issuer names"
  print "-q hide less interesting results"
  sys.exit(1)

def sel(q, params = None, MAX = 10000):
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

q = "select `X509v3 extensions:Netscape Cert Type`, count(*) as c from valid_certs "\
   +"group by `X509v3 extensions:Netscape Cert Type` order by c desc;"

print "Show wierd netscape extension use:"
r = sel(q)
for ext, c in r:
  print "extension: %55s seen %d times " %(ext, c)
print

# doesn't include netscape weirdness
# doesn't include key usage 
q = "select certid, subject, issuer, "+skid+", locate('CA', "\
    +"`X509v3 extensions:Netscape Cert Type`), locate('true', "\
    +"`X509v3 extensions:X509v3 Basic Constraints:CA`)"\
    +" from valid_certs where " \
    +"locate('true', `X509v3 extensions:X509v3 Basic Constraints:CA`) or "\
    +"locate('CA', `X509v3 extensions:Netscape Cert Type`)"
    
print q

if not only_interesting:
  r = sel(q)
  print "Found %d CA Certs" % len(r)
  print
  for certid, subject, issuer, sk, ns, basic in r:
    print "subject=isssuer: %s has skid: %s certid: %d Netscape CA: %s Basic CA: %s"%(subject==issuer,sk!=None,certid, ns!=None, basic!=None)
    print " subject: " + subject
  print

q = "select issuer, `X509v3 extensions:X509v3 Authority Key Identifier:keyid`, "\
    +"count(*) as c from valid_certs where not locate('true', "\
    +"`X509v3 extensions:X509v3 Basic Constraints:CA`) or "\
    +"`X509v3 extensions:X509v3 Basic Constraints:CA` is null "\
    +"and (not locate('CA', `X509v3 extensions:Netscape Cert Type`) or "\
    +"`X509v3 extensions:Netscape Cert Type` is null) "\
    +"group by issuer, `X509v3 extensions:X509v3 Authority Key Identifier:keyid` "\
    +"order by c desc;"

print "Determining Issuer Importance"
print q

r = sel(q)
print "Found %d distinct issuers used to sign leaves" % len(r)
t = [(i, k, c) for i, k, c in r]

for issuer, kid, c in t:
  n = issuer
  q = "select count(*), count(distinct `RSA Public Key:Modulus`) from valid_certs where subject = %s"
  p = (issuer,)
  if kid:
    q += " and `X509v3 extensions:X509v3 Subject Key Identifier` = %s"
    p = (issuer,kid)
  r = sel (q, p)
  if not full_issuer_name: 
    n = getOrgs(issuer)
    n.extend(getCountries(issuer))
  i = True
  if only_interesting:
    i = r[0][0] != 1 or r[0][1] != 1
  if i: print "%d leaves (match %d certs with %d unique keys) issuer: %s %s" % (c, r[0][0], r[0][1], n, kid)

#pdb.set_trace();

#if __name__ == "__main__":
#  main()

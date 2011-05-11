#!/usr/bin/env python
import MySQLdb
import getopt, pdb, re, sys

akid = "`X509v3 extensions:X509v3 Authority Key Identifier:keyid`"
skid = "`X509v3 extensions:X509v3 Subject Key Identifier`"
ca = "`X509v3 extensions:X509v3 Basic Constraints:CA`"

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
    r.append(x.group(2).upper())
  return r

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
i_to_c = {}
c_to_c = {}
o_to_c = {}
multis = []
for issuer, kid, c in t:
  n = issuer
  q = "select count(*), count(distinct `RSA Public Key:Modulus`) from valid_certs where subject = %s"
  p = (issuer,)
  countries = getCountries(issuer)
  orgs = getOrgs(issuer)
  if len(countries) > 1:
  	multis.append(issuer, countries)
  if len(orgs) > 1:
  	multis.append(issuer, orgs)
  v = i_to_c.get(issuer, [])
  v.append(c)
  i_to_c[issuer] = v
  
  for co in countries:
    v = c_to_c.get(co, [])
    v.append(c)
    c_to_c[co] = v
  for org in orgs:
    v = o_to_c.get(org, [])
    v.append(c)
    o_to_c[org] = v
  
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

print "Totals by Org:"
for org in o_to_c.keys():
	print "%s, %d, %d" %( org, sum(o_to_c[org]), len(o_to_c[org]))
print "Totals by Country:"
for con in c_to_c.keys():
	print "%s, %d, %d" %(con, sum(c_to_c[con]), len(c_to_c[con]))

print "Totals by issuer:"
for iss in i_to_c.keys():
	print "%s, %d, %d" %( iss, sum(i_to_c[iss]), len(i_to_c[iss]))

print "Multis: %r" % multis

q = "select subject from roots;"
r = sel(q)
conts = set()
orgs = set()

for sub in r:
  countries = getCountries(sub[0])
  orgzz = getOrgs(sub[0])
  for co in countries:
    conts.add(co)
  for org in orgzz:
    orgs.add(org)

print "Countries with roots: "
for c in conts: print c

print "Orgs with roots:"
for o in orgs: print o

#pdb.set_trace();

#if __name__ == "__main__":
#  main()

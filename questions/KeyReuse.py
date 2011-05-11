#!/usr/bin/env python
import MySQLdb
import getopt, pdb, re, sys

DEBUG = False

akid = "`X509v3 extensions:X509v3 Authority Key Identifier:keyid`"
skid = "`X509v3 extensions:X509v3 Subject Key Identifier`"
ca = "`X509v3 extensions:X509v3 Basic Constraints:CA`"


sys.path.append("..")
from dbconnect import dbconnect
readb,rdbc = dbconnect()

try:
  opts, args = getopt.getopt(sys.argv[1:], "",[])
  
  for o, a in opts:
    pass
    #if o == '--from':
    #  INPUT_TABLE = a
    #elif o == '--into':
    #  ALL_NAMES = a

except getopt.GetoptError, err:
  print err
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
q = "select count(*), certid, RSA_Modulus_bits " \
    +"from valid_certs where "\
    +"locate('TRUE', `X509v3 extensions:X509v3 Basic Constraints:CA`) " \
	  +"group by `RSA Public Key:Modulus`" \
	  +"having count(distinct subject, `Validity:Not After`) > 1 " \
    +"order by RSA_Modulus_Bits desc;"


print "This analysis is of CA certs, defined by the x509v3 basic constraint CA"
print "It excludes those certificates uisng Netscape style CA certs"
print "include those with locate('CA', `X509v3 extensions:Netscape Cert Type`)"
print q

r = sel(q)

print "Found %d groups of CA certs sharing keys" % len(r)
print

f = [(c, certid, bits) for c, certid, bits in r]

for c, certid, bits in f:
  print "%d CA certs of %s bits" %(c, bits)
  r = sel("select certid, `X509v3 extensions:Netscape Cert Type`, "\
      +"`X509v3 extensions:X509v3 Basic Constraints:CA`, issuer, subject, "\
      +"startdate, enddate "\
      +"from valid_certs where `RSA Public Key:Modulus` = "\
      +"(select `RSA Public Key:Modulus` from valid_certs where certid = %s)", (certid,))
  t = [(certid, ns, ca, i, s, nb, na) for certid, ns, ca, i, s, nb, na in r]
  if c == len(r): print " Total valid certs using this key also %s" % len(r)
  else: 
    print " ** Valid certs using this key != simple CA count: %s" % len(r) 
    for certid, ns, ca, i, s, nb, na in t:
      print " **  certid: %s Netscape Cert: %s x509 CA: %s" % (certid, ns, ca)
  earlys, earlye, lates, latee, roots, other = None, None, None, None, set(), []
  s_orgs, s_c, i_orgs, i_c = set(), set(), set(), set()
  for certid, ns, ca, i, s, nb, na in t:
    if earlys == None: earlys = (nb, certid, na)
    if earlye == None: earlye = (na, certid, nb)
    if lates == None: lates= (nb, certid, na)
    if latee == None: latee= (na, certid, nb)
    if (nb < earlys[0]): earlys = (nb, certid, na)
    if (na < earlye[0]): earlye = (na, certid, nb)
    if (nb > lates[0]): lates = (nb, certid, na)
    if (na > latee[0]): latee = (na, certid, nb)
    if i == s: roots.add(certid)
    for c in getCountries(s): s_c.add(c)
    for c in getCountries(i): i_c.add(c)
    for o in getOrgs(s): s_orgs.add(o)
    for o in getOrgs(i): i_orgs.add(o)
    other.append(certid)
    #if DEBUG: if len(cseeddn) != 1: print s
    #if DEBUG: print "Countries %s" % cseen
    #if DEBUG: if len(oseen) != 1: print s
    #if DEBUG: print "Orgs %s" % oseen
  print "  Issuer Countries: %s" % list(i_c)
  print "  Issuer Orgs: %s" % list(i_orgs)
  if len(s_c) > 1: print "**",
  print "  Subject Countries: %s" % list(s_c)
  if len(s_orgs) > 1: print "**",
  print "  Subject Orgs: %s" % list(s_orgs)
  print "  Earliest start was %s with certid %s (expires %s)" % earlys
  print "  Earliest expiration %s with certid %s (started %s)" % earlye
  print "  Latest start was %s with certid %s (expires %s)" % lates
  print "  Latest expiration %s with certid %s (started %s)" % latee 
  if latee[1] != earlys[1]: print "**",
  print "  Diff latest and earliest expiry: %s" % (latee[0] - earlye[0])
  print "  Total Validity Period: %s" % (latee[0] - earlys[0]) 
  if len(roots) > 0: print "  Possible roots certids: %s" % [int(x) for x in roots] 
  print "  Certids in group: %s" % [int(x) for x in other]
  print



#pdb.set_trace();

#if __name__ == "__main__":
#  main()


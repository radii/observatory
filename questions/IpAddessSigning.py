#!/usr/bin/env python
import MySQLdb
import getopt, pdb, re, sys


akid = "`X509v3 extensions:X509v3 Authority Key Identifier:keyid`"
skid = "`X509v3 extensions:X509v3 Subject Key Identifier`"
ca = "`X509v3 extensions:X509v3 Basic Constraints:CA`"

# db init

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

def sel(q, params = None, MAX = 1000):
 rdbc.execute(q, params)
 return rdbc.fetchmany(MAX)

# query selects distinct cobminations of issuer and AKID for certs with
# names that look like IP addresses.
q= r"select distinct issuer," + akid + r"from valid_certs natural join names "\
   + r" where name rlike '^([0-9]{1,3}\\.){3}[0-9]{1,3}$'"

r = sel(q)
print "Found %d issuer's certificates that sign IP addresses"% len(r)
print
for issuer, s in r:
  print issuer
print


# query selects distinct combinations of issuer and AKID for certs with names
# that appear to be RFC 1918 space (192.168.*.*, 10.*.*.* 172.16-31.*.*)

q= r"select distinct issuer, " + akid + r"from valid_certs natural join names"\
    + r" where name rlike '^(10\\.[0-9]{1,3}\\.|192\\.168\\.|172\\."\
    + r"(16|17|18|19|2[0-9]|30|31)\\.)[0-9]{1,3}\\.[0-9]{1,3}$';"

r = sel(q)
print "Found %d issuers certs that sign RFC 1918 IP addresses" % len(r)
print 
iss = [(issuer, kid) for issuer, kid in r]
for issuer, kid in iss:
  print issuer
  p = (issuer)
  q = "select certid from valid_certs where subject=%s"
  if kid:
    q += "and " + skid + "=%s"
    p = (issuer, kid)
  q += ";"
  r = sel(q, p)
  
  print "  %d issuer match skid = %59s Cert IDs: %s" % (len(r), kid, 
        repr([int(x[0]) for x in r]))
print


q2= r"select count(*) as c, name, issuer from valid_certs join names"\
     + r" where name rlike '^([0-9]{1,3}\\.){3}[0-9]{1,3}$' group by issuer "\
     + r"order by c;"

print "Numbers of IPs signed per issuer"
print "# IPs signed, example IP, issuer Name"
for co, name, issuer in sel(q2):
  print str(co).ljust(5), name.ljust(15), issuer

#pdb.set_trace();

#if __name__ == "__main__":
#  main()

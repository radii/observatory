#!/usr/bin/env python
import MySQLdb
import sys
sys.path.append("..")
from dbconnect import dbconnect
db,dbc = dbconnect()

q = """
select distinct `Serial Number` as sn, Subject, Issuer
from valid_certs natural join (
  select certid 
  from blacklist natural join valid_key_hashes
) as x 
where `Serial Number` not in 
  (select `Serial Number` from revoked)
"""
dbc.execute(q)

revoked = 0
not_revoked = 0
issuers = {}
good = {}
bad = {}

for (sn,subject,issuer) in dbc.fetchall():
  issuers[issuer] = True
  good.setdefault(issuer,0)
  bad.setdefault(issuer,0)

  if "(0x" in sn:
    # value looks like " 848003 (0xcf083)"
    #print sn
    dec, sep, hexd = sn.partition("(0x")
    hexd, sep, nothing = hexd.partition(")")
    assert hex(int(dec.strip()))[2:] == hexd
  else:
    # value looks like 01:00:00:00:00:01:17:9c:2e:ee:76
    hexd = sn.replace(":","")

  target = hexd.upper()

  q = """
  select count(`Serial Number`) from revoked where `Serial Number` = "%s"
  """ % target
  #print q
  dbc.execute(q)
  res = dbc.fetchone()[0]
  if res:
    print subject, "(revoked)"
    good[issuer] += 1
    revoked +=1
  else:
    print subject, "(not revoked)"
    not_revoked +=1
    bad[issuer] += 1

g = b = m = 0
for issuer in issuers.keys():
  if good[issuer]:
    if bad[issuer]:
      print "Mixed", good[issuer], "good,", bad[issuer], "bad;",
      m+=1
    else:
      print "Good", good[issuer],
      g+=1
  else:
    print "Bad", bad[issuer],
    b+=1
  print issuer

print revoked, "revoked"
print not_revoked, "not revoked"
print g, "good CAs"
print m, "mixed CAs"
print b, "bad CAs"

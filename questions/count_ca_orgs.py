#!/usr/bin/env python
import MySQLdb
import re
import sys
sys.path.append("..")
from dbconnect import dbconnect
db,dbc = dbconnect()

q = "SELECT DISTINCT ca_subj FROM ca_skids"
dbc.execute(q)

orgs = {}
count = 0
results = dbc.fetchall()
for (subj,) in results:
  x = re.search("O=([^=]+), [A-Z][A-Z]?=", subj)
  if not x:
    count +=1
  else:
    org = x.group(1)
    if org not in orgs:
      count +=1
      orgs[org] = True

print count, "organisations hold CA certs"

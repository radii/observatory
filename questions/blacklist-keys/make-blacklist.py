#!/usr/bin/env python

import glob
import MySQLdb

import sys
sys.path.append("..")
from dbconnect import dbconnect
db,dbc = dbconnect()

q = "DROP TABLE IF EXISTS blacklist"
dbc.execute(q)

q = "CREATE TABLE blacklist (half_sha1 CHAR(20))"
dbc.execute(q)

for bfile in glob.glob("blacklist*"):
  lines = open(bfile).readlines()
  for line in lines:
    l = line.strip()
    if len(l)==20 and l[0] != "#":
      q = "INSERT INTO blacklist VALUE ('%s')" % l
      dbc.execute(q)

q = "CREATE INDEX sha ON blacklist(half_sha1)"
dbc.execute(q)

#!/usr/bin/env python

# This script cleans up after a bug in --readable that left some certs missing
# from the readable table :/

import dbconnect
import openssl_dump
import os

db,dbc = dbconnect.dbconnect()
db1,dbc1 = dbconnect.dbconnect()

q = """
select fingerprint,path from all_certs 
where fingerprint not in (
  select fingerprint from readable
)
"""
print q
dbc.execute(q)
batch = dbc.fetchmany(1000)
while batch:

  fds = []
  for fprt, path in batch:
    # Let the IO subsystem figure out an efficient way to suck all these certs
    # into RAM
    f = os.open(path, os.O_NONBLOCK)
    fds.append(f)
    os.read(f,2048)

  q = []
  for fprt,path in batch:
    print path
    pem_certs, output_texts, fingerprints = openssl_dump.toOpensslText(path)
    try:
      n = fingerprints.index(fprt)
      q.append('("%s", "%s")' % (db1.escape_string(fprt), db1.escape_string(output_texts[n])))
    except ValueError:
      print "Fingerprint", fprt, "is not in"
      print fingerprints

  q = 'INSERT INTO readable VALUES ' + ', '.join(q)
  dbc1.execute(q)
 
  for fd in fds: os.close(fd)
  batch = dbc.fetchmany(1000)


#!/usr/bin/env python

# Some certs WOULD be valid if they had the appropriate intermediate certs
# attached to them.  We could ignore that, except that Firefox (and maybe
# other browsers) actually cache intermediate certs, causing these certs to
# become valid if you've been surfing for a while!  So this code attempts to
# compute whether there are any such certs about!

# We do not attempt to distinguish between certs that are transvalid for
# Mozilla or MSIE: if it's transvalid for either, we call it transvalid.

import sys
import MySQLdb
from openssl_dump import enc,verifyOneCert, ALL_VERIFY_ARGS, SERVER_VRFY, dataToCerts
from stitch_tables import TableStitcher
VALID_TABLE = "valid_certs"

if len(sys.argv) <= 1 or sys.argv[1] == "--help":
  print "Usage:"
  print "  transvalid.py <certs table 0> [certs table 1] .."
  print ""
  print "Run this on the raw certs tables (certs0,certs0b .. certs15) to compute"
  print "which of them are transvalid, using valid_certs as the available store of"
  print "valid intermediate CA certificates."
  sys.exit(1)

modify_tables = sys.argv[1:]

from dbconnect import dbconnect
db,dbc = dbconnect()

fetch_revalidatable = """
SELECT %(t)s.path, %(t)s.id, %(valid_certs)s.path, %(t)s.fingerprint, %(t)s.fetchtime
FROM %(t)s join %(valid_certs)s 
ON %(t)s.issuer = %(valid_certs)s.subject and (
   (%(t)s.`X509v3 extensions:X509v3 Authority Key Identifier:keyid` is null and
   %(valid_certs)s.`X509v3 extensions:X509v3 Subject Key Identifier` is null) 
   or
   %(t)s.`X509v3 extensions:X509v3 Authority Key Identifier:keyid` =
   %(valid_certs)s.`X509v3 extensions:X509v3 Subject Key Identifier`
)
WHERE not %(t)s.valid and
      (locate("unable to get local issuer certificate", %(t)s.moz_valid) or
      locate("unable to get local issuer certificate", %(t)s.ms_valid) )
GROUP BY %(t)s.fingerprint, %(valid_certs)s.path
"""
update_revalidated = """
UPDATE %(t)s
SET valid=%(valid)r,
    transvalid="%(reval)s" 
WHERE fingerprint="%(fprt)s"
"""


def add_trandsvalid(t):
  q = "ALTER TABLE %s ADD COLUMN (transvalid text)" % t
  print q
  try:
    dbc.execute(q)
  except Exception, e:
    assert "Duplicate column name" in `e`, e
  q = "CREATE INDEX fprt ON %s(fingerprint)" % t
  print q
  try:
    dbc.execute(q)
  except Exception, e:
    assert "Duplicate key name" in `e`, e
  q = "CREATE INDEX path ON %s(path)" % t
  print q
  try:
    dbc.execute(q)
  except Exception, e:
    assert "Duplicate key name" in `e`, e

def revalid(table):
  validated = {} # Store validated ids in here
  #add_trandsvalid(VALID_TABLE)
  add_trandsvalid(table)
  ts = {"t":table,"valid_certs":VALID_TABLE}
  q = fetch_revalidatable % ts
  print q
  db1,dbc1 = dbconnect()
  dbc1.execute(q)
  res = dbc1.fetchmany(1000)
  while res:
    print ".",
    # Sometimes this 
    for certpath, certid, extrapath, fprt, fetchtime in res:
      # Extrapath contains a cert[chain] that may make something in certpath
      # valid, so rerun validation that way...
      certs = dataToCerts(open(certpath, 'rb').read())
      certs = map(enc, certs)
      ecerts = dataToCerts(open(extrapath, 'rb').read())
      ecerts = map(enc, ecerts)
      q = "select min(id) from `%s` where path='%s'" % (table, certpath)
      dbc.execute(q)
      chain_start = dbc.fetchone()[0]
      pos_in_chain = certid - chain_start
      tcert = certs[pos_in_chain]
      others = certs[:pos_in_chain] + certs[pos_in_chain +1:] + ecerts
      ts["id"] = certid
      ts["fprt"] = fprt
      revalidate_one_cert(tcert, others, ts, pos_in_chain, validated, fetchtime)

    res = dbc1.fetchmany(1000)

def revalidate_one_cert(tcert, others, tables, pos_in_chain, validated, tstamp):
  # reevaluate certs with ecerts now in the chain
  extra_args = ["-attime", "%d" % tstamp]
  if pos_in_chain == 0: extra_args += SERVER_VRFY
  reval = verifyOneCert(tcert, others, ALL_VERIFY_ARGS, extra_args, verbose=True)
  tables["reval"] = db.escape_string(reval)
  if reval == "Yes": tables["valid"] = 1
  else:              tables["valid"] = 0
  # save us from writing transvalid in a lot of unecessary cases
  if "unable to get local issuer certificate" not in reval:
    # don't overwrite if there were several transvalidation paths
    if tables["fprt"] not in validated:
      validated[tables["fprt"]] = True
      q = update_revalidated % tables
      print q
      dbc.execute(q)
  #if reval=="Yes":
  #  print "valid!"
  #  TableStitcher(tables["t"], load_invalid=False).stitch(VALID_TABLE)

map(revalid, modify_tables)

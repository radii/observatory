#!/usr/bin/env python
import MySQLdb
import getopt, pdb, re, sys
import time

# Make tables mapping subject common names and subject alternate names to
# certids

ALT_COLUMN_NAME = 'X509v3 extensions:X509v3 Subject Alternative Name'
FETCH_COUNT = 1000
HARMLESS=False
log = False

from dbconnect import dbconnect
readdb, rdbc = dbconnect()
writedb, wdbc = dbconnect()

assert rdbc != wdbc # :)
assert readdb != writedb # :)

INPUT_TABLE = "valid_certs"

SAN_TABLE_NAME = 'SANToCert'
SCN_TABLE_NAME = 'SCNToCert'
ALL_NAMES = 'names'

try:
  opts, args = getopt.getopt(sys.argv[1:], "",["from=","into=","san_into=", "scn_into="])
  
  for o, a in opts:
    if o == '--from':
      INPUT_TABLE = a
    elif o == '--into':
      ALL_NAMES = a
    elif o == '--san_into':
      SAN_TABLE_NAME = a
    elif o == '--scn_into':
      SCN_TABLE_NAME = a
except getopt.GetoptError, err:
  print err
  print "Usage: [--from <table name to load from>] [--into <table to load into>]"
  print "       [--san_into <SAN to cert tbl>] [--scn_into <scn to cert tbl>]"
  sys.exit(1)

all_names = {}

def createNameTable(name):
  wdbc.execute("drop table if exists %s" % name)
  tdef = """
  create table %s (
    name varchar(996), 
    certid integer
  )""" % name
  wdbc.execute(tdef)
  print tdef

def insertNames(names, table):
  q = "insert ignore into " +table+ " (name, certid) values (%s, %s)"
  # create list of tuples for insertion
  toInsert = []
  for cid, namelist in names.items():
    for name in namelist:
      toInsert.append((name, cid))
  wdbc.executemany(q, toInsert)

def createIndex(tname):
  q ="create index pair on %s(certid, name)" % tname 
  wdbc.execute(q)
  print q


def createIndicies2(tname):
  q ="create index n on %s(name)" % tname 
  wdbc.execute(q)
  print q
  q ="create index c on %s(certid)" % tname 
  wdbc.execute(q)
  print q

def createUniqueness(tname):
  q = "ALTER IGNORE TABLE %s ADD UNIQUE KEY ukey (certid,name)" % tname
  wdbc.execute(q)
  print q


def insertSANs():
  q = "select certid, `%s` from %s where `%s` is not null " \
       % (ALT_COLUMN_NAME, INPUT_TABLE, ALT_COLUMN_NAME)
  print "Running query: " + q
  rdbc.execute(q)
  r = rdbc.fetchmany(FETCH_COUNT)
  n = 0
  while r:
    start = time.time()
    sn = n
    names = {}
    for certid, altnames in r:
      n+=1
      s = altnames.replace("===", ':', 1)
      entries = s.split("DNS:")[1:] #get rid of any pre DNS: fluff
      if log: print "new row: ", s, len(entries)
      for f in entries:
        end = f.find(", ")
        spot = names.setdefault(certid, [])
        if end > -1: spot.append(f[:end]) 
        else: spot.append(f)
    if not HARMLESS: insertNames(names, SAN_TABLE_NAME)
    print (n -sn) / (time.time() - start), "ups"
    r = rdbc.fetchmany(FETCH_COUNT)
  print "Processed", n, "SANs fields"
  #print len(names.keys()), sum([len(x) for x in names.values()])

def insertSCNs():
  q = "select certid, Subject from %s where Subject is not null" % INPUT_TABLE
  print "Running query: ", q
  rdbc.execute(q)
  r = rdbc.fetchmany(FETCH_COUNT)
  WCN_RE = re.compile('(.*?)/[\._a-zA-Z0-9]+=.*')
  n = 0
  while r:
    start = time.time()
    sn = n
    names = {}
    for certid, subject in r:
      n += 1
      entries = subject.split("CN=")[1:] # loose pre CN fluff
      for f in entries:
        spot = names.setdefault(certid, [])
        m = WCN_RE.match(f)
        if m:
          f = m.group(1)
        end = f.find(", ")
        if end > -1: f = f[:end]
        spot.append(f)
    if not HARMLESS: insertNames(names, SCN_TABLE_NAME)
    print (n - sn) / (time.time() - start), "ups"
    r = rdbc.fetchmany(FETCH_COUNT)
  print "Processed", n, "Subject fields"


if not HARMLESS: createNameTable(SAN_TABLE_NAME)
if not HARMLESS: createNameTable(SCN_TABLE_NAME)

if not HARMLESS: createUniqueness(SAN_TABLE_NAME)
if not HARMLESS: createIndicies2(SAN_TABLE_NAME)

if not HARMLESS: createUniqueness(SCN_TABLE_NAME)
if not HARMLESS: createIndicies2(SCN_TABLE_NAME)

# generally harmless because of uniqueness constraints
insertSCNs()
insertSANs()

if not HARMLESS: createNameTable(ALL_NAMES)

if not HARMLESS: createUniqueness(ALL_NAMES)
if not HARMLESS: createIndicies2(ALL_NAMES)

q = "INSERT ignore INTO %s (name, certid) select name, certid from %s"\
    % (ALL_NAMES, SAN_TABLE_NAME)
if not HARMLESS: wdbc.execute(q)
q = "INSERT ignore INTO %s (name, certid) select name, certid from %s"\
    % (ALL_NAMES, SCN_TABLE_NAME)
if not HARMLESS: wdbc.execute(q) 

print len(all_names.items())

#pdb.set_trace();

#if __name__ == "__main__":
#  main()

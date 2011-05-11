#!/usr/bin/env python

import MySQLdb,os.path, sys
from subprocess import PIPE, Popen
from urllib import urlretrieve
import sys
sys.path.append("..")
from dbconnect import dbconnect
db,dbc = dbconnect()

CMD = ["openssl", "crl", "-noout", "-text", "-inform", "der", "-in"]

def fetch_crl(uri):
  print "Fetching", uri
  if uri.startswith("ldap:"): return
  fn = uri.replace(os.path.sep,"-")
  if not os.path.isfile(fn):
    try:
      filen, headers = urlretrieve(uri, fn)
    except IOError,e:
      print "ERROR FETCHING", uri
      print e
      return
    assert fn == filen

  cmd = CMD + [fn]
  proc = Popen(cmd, stdout=PIPE, stdin=PIPE)
  stdout, stderr = proc.communicate()
  if stderr:
    print "ERROR reading CRL:"
    print stderr
    sys.exit(1)
  for line in stdout.split("\n"):
    l = line.strip()
    if l.startswith("Serial Number: "):
      sn = l.partition("Serial Number: ")[2]
      q = "INSERT INTO revoked VALUE ('%s', '%s')" % \
                                       (db.escape_string(uri), db.escape_string(sn))
      print q
      dbc.execute(q)

def mk_revoked_table():
  q = "DROP TABLE IF EXISTS revoked"
  print q
  dbc.execute(q)
  q = "CREATE TABLE revoked (uri text, `Serial Number` varchar(100))"
  print q
  dbc.execute(q)
  q = "CREATE INDEX sn ON revoked(`Serial Number`)"
  print q
  dbc.execute(q)


def main():
  mk_revoked_table()
  q = """
  select `X509v3 extensions:X509v3 CRL Distribution Points`
  from valid_certs natural join 
    (select certid 
     from blacklist natural join valid_key_hashes) as x """
  dbc.execute(q)
  results = dbc.fetchall()
  fetched = {}
  for (crl,) in results:
    print crl
    if crl:
      for word in crl.split():
        if word.startswith("URI==="):
          uri = word.partition("URI===")[2]
          print "uri", uri
          if uri not in fetched:
            fetch_crl(uri)
            fetched[uri] = True

if __name__ == "__main__":
  main()

#!/usr/bin/env python

import MySQLdb,os.path, sys
from subprocess import PIPE, Popen
from urllib import urlretrieve
import sys
sys.path.append("..")
from dbconnect import dbconnect
db,dbc = dbconnect()


def main():
  q = """
  select distinct `X509v3 extensions:X509v3 CRL Distribution Points`
  from valid_certs"""
  dbc.execute(q)
  results = dbc.fetchall()
  fetched = {}
  for (crl,) in results:
    #print crl
    if crl:
      for word in crl.split():
        if word.startswith("URI==="):
          uri = word.partition("URI===")[2]
          #print "uri", uri
          if uri not in fetched:
            print uri
            fetched[uri] = True

if __name__ == "__main__":
  main()

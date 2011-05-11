#!/usr/bin/env python

# Collect a client report from the decentralised observatory

from dbconnect import dbconnect
db,dbc = dbconnect()

def import_cert(path):
  try:
    fields = hacky_parse(parsed_cert)
  except:
    print "Error parsing", path + "\n" + parsed_cert
    raise


#!/usr/bin/env python

# Make the valid_certs table as a subset of the all_certs table

import column_counter
import MySQLdb
from dbconnect import dbconnect
db, dbc = dbconnect()
dbc.execute("DESC valid_certs")
columns = ["`"+c[0]+"`" for c in dbc.fetchall()]
q = """
insert into valid_certs
  select %s from all_certs
  where valid
""" % ", ".join(columns)
print q
dbc.execute(q)

#!/usr/bin/env python

import MySQLdb
import sys

# Calculate the maximum widths of the various columns (cert fields)
# so that we can use optimal varchars for these columns in valid_certs,
# for the depressing reason that MySQL won't index blobs.

def main():
  table = "certs"
  if len(sys.argv) > 1:
    table = sys.argv[1]

  widths = column_widths(table)
  print_column_table(widths)

def print_column_table(widths):
  ws = widths[:]
  ws.sort()
  for column, width  in ws:
    print "%-70s" % column, width

from dbconnect import dbconnect
db, dbc = dbconnect()

def column_widths(tablename, valid_only=False):
  "Return a list [(column_name, maximum_width)] of the columns in tablename."
  print "about to desc: ", tablename
  dbc.execute("DESC " + tablename)

  q = []
  columns = [c[0] for c in dbc.fetchall()]
  for cname in columns:
    q.append("max(length(`%s`)) " % (cname))

  q = "select " + ", ".join(q) + "from %s" % tablename
  if valid_only:
    q += ' where valid'
  dbc.execute(q)
  results =dbc.fetchall()[0]
  widths = zip(columns,results)
  widths.sort()
  return widths

if __name__ == "__main__":
  main()

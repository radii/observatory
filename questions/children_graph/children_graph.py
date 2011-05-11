#!/usr/bin/env python
import MySQLdb
import re

import sys
sys.path.append("..")
from dbconnect import dbconnect
db,dbc = dbconnect()

# LOG = 0 | 1
LOG = 0

def get_header(LOG,n):
  if LOG:
    header = """newgraph
    xaxis size 5  label : %d root CAs
    yaxis size 4 log label : Number of leaves signed (+1)
    newcurve
    marktype none
    color 1 0 0
    linetype solid
    pts
    """ %n
  else:
    header = """newgraph
    xaxis size 5  label : %d root CAs
    yaxis size 4 label : Number of leaves signed 
    newcurve
    marktype none
    color 1 0 0
    linetype solid
    pts
    """%n
  return header

def graph_by_root(roots, log):

  if log:
    f = open("ca_usage_log.jgraph","w")
  else:
    f = open("ca_usage.jgraph","w")
  f.write(get_header(log,len(roots)))
  data = [r.ancestor_leaves for r in roots]
  data.sort()
  data.reverse()
  for n, leaves in enumerate(data):
    f.write("%d %d\n" % (n, leaves +log))  # log scales can't go to 0 :)


def main():
  q = """
  select ca_subj,sum(children) as c
  from ca_skids group by ca_subj 
  order by c desc"""
  dbc.execute(q)
  f = open("ca_usage.jgraph","w")
  f.write(get_header(LOG))
  n = 1
  for (subject, children) in dbc.fetchall():
    f.write("%d %d\n" % (n, children + LOG))  # log scales can't go to 0 :)
    n +=1

if __name__ == "__main__":
  main()

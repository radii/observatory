#!/usr/bin/env python

import sys
sys.path.append("../..")
import MySQLdb
import re
import children_graph
from SubordinateTracking import findSignedSubordinates, countSignedLeaves
from disclosure.disclosure import extract_ca_name
from math import log


sys.path.append("..")
from dbconnect import dbconnect
db,dbc = dbconnect()

fetch_roots = """
SELECT id, Subject, `X509v3 extensions:X509v3 Subject Key Identifier`,
       moz_valid, ms_valid
FROM roots
GROUP BY fingerprint
"""

# Map each Subject field to the root we see it sitting below
subjects_to_roots = {}
subjects_to_ids = {}
node_id = 0
all_nodes = {}
names_to_cas = {}

class CA:
  def __init__(self, subject, skid, moz_v, ms_v, trans_v=None, 
                       root=None, issuer=None, akid=None):
    self.subj = subject
    self.skid = skid
    self.issuer = issuer
    self.akid = akid
    self.moz_v, self.ms_v, self.trans_v = moz_v, ms_v, trans_v
    self.lineage(root)

    self.name = extract_ca_name(subject)
    names_to_cas.setdefault(self.name,[]).append(self)


    child_CAs_details = findSignedSubordinates(subject, skid, recurse=False)
    self.child_CAs= [CA(csubj,cskid,moz_v,ms_v,root=self.root) 
                                    for _id,csubj,ciss,cskid in child_CAs_details]
    self.child_leaves = countSignedLeaves(subject, skid)
    self.n_ancestors =  len(self.child_CAs) \
                      + sum([c.n_ancestors for c in self.child_CAs])
    self.ancestor_leaves =  self.child_leaves \
                          + sum([c.ancestor_leaves for c in self.child_CAs])
  def lineage(self,root):
    global node_id
    self.id = node_id
    all_nodes[node_id] = self
    node_id += 1
    if root: self.root = root
    else: self.root = self
    if self.subj in subjects_to_roots:
      subjects_to_roots[self.subj].append(self.root)
      subjects_to_ids[self.subj].append(self.id)
    else:
      subjects_to_roots[self.subj] = [self.root]
      subjects_to_ids[self.subj] = [self.id]
    
  def __str__(self, tabs=0):
    out = "CA:"+  self.subj + "\n"
    out += ("moz: %r , ms: %r" % (self.moz_v, self.ms_v)) + "\n"
    out += "%d total sub-CAs, %d immediate\n" % \
                                         (self.n_ancestors, len(self.child_CAs))
    out += "%d total leaves, %d immediate\n"  % \
                                         (self.ancestor_leaves, self.child_leaves)
    if tabs:
      out = "\n".join([tabs*"\t" + l for l in out.split("\n")])+"\n"
    return out

  def print_children(self, base_tabs=0):
    out = ""
    for c in self.child_CAs:
      out += c.__str__(tabs=base_tabs + 1)
      if c.child_CAs:
        out += c.print_children(base_tabs=base_tabs+1)
    return out
 
colour_table = {
  0 : "0.9 0.0 0.0",
  1 : "0.8 0.5 0.0",
  2 : "0.9 0.9 0.0",
  3 : "0 0.9 0",
  4 : "0 0.8 0.8",
  5 : "0 0 0.9"}

colour_table = {
  0 : "violet",
  1 : "blue",
  2 : "green",
  3 : "yellow",
  4 : "orange",
  5 : "red"}


def ca_colour(n_children):
  "Figure out what colour to render a CA as a fn of the number of children"
  if n_children == 0:
    return "black"
  n = int(log(n_children) / log(10))
  return colour_table[n]

def dot_description(nodes):
  total_children = sum([n.child_leaves for n in nodes])
  ms_v = "Yes" in [n.ms_v for n in nodes]
  moz_v = "Yes" in [n.moz_v for n in nodes]
  root_holder = True in [n.root == n for n in nodes]

  name = nodes[0].name
  for n in nodes:
    assert n.name == name, "mismatched name in " + `[n.name for n in nodes]`
  
  desc = '"%s" [' % name
  if root_holder:
   if ms_v:
     if moz_v:
       desc += "shape=box"
     else:
       desc += "shape=hexagon"
   else:
     desc += "shape=diamond"
  else:
   desc += "shape=ellipse"
  desc += ',color=%s' % ca_colour(total_children)
  desc += "]"
  return desc
   

DEFAULT_STYLE="node [shape=ellipse];"
ROOT_STYLE=""
def render_graph(root_nodes):
  outfile = open("colour_CAs.dot","w")
  outfile.write("digraph G {\n")
  outfile.write('  size = "20,20";\n')

  for name,nodes in names_to_cas.items():
    outfile.write(dot_description(nodes) +";\n")

  for id,node in all_nodes.items():
    for child in node.child_CAs:
      outfile.write(' "%s" -> "%s" [color=grey];\n' % (node.name, child.name))

  outfile.write("}")

def main():
  root_nodes = []
  q = fetch_roots
  print q
  dbc.execute(q)
  roots = dbc.fetchall()
  for r in roots:
    _certid, subj, skid, moz_v, ms_v = r
    ca = CA(subj,skid,moz_v,ms_v)
    print ca
    print ca.print_children()
    root_nodes.append(ca)

  s = m = 0
  for subj, roots in subjects_to_roots.items():
    if len(roots) == 1: s += 1
    else: m += 1
  print s, "Subjects appear under one root"
  print m, "Subjects appear under several"

  children_graph.graph_by_root(root_nodes,0)
  children_graph.graph_by_root(root_nodes,1)

  render_graph(root_nodes)

  
if __name__ == "__main__":
  main()

#!/usr/bin/env python

import re
cmatch = re.compile("[^A-Z]C=([A-Z][A-Z])")
f = open("ca-tree.txt","r").read()
hits = cmatch.findall(f)
countries = {}
for h in hits:
  countries[h] = True

cs = countries.keys()
cs.sort()
print cs


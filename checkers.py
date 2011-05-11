from dbconnect import dbconnect
db,dbc = dbconnect()

blob = """009239d5348f40d1695a745470e1f23f43
00b0b7133ed096f9b56fae91c874bd3ac0
00d7558fdaf5f1105bb213282b707729a3
00d8f35f4eb7872b2dab0692e315382fb0
00e9028b9578e415dc1a710a2b88154447
00f5c86af36162f13a64f54f6dc9587c06
047ecbe9fca55f7bd09eae36e10cae1e
392a434f0e07df1f8aa305de34e0c229
3e75ced46b693021218830ae86a82a71
72032105c50c08573d8ea5304efee8b0
9239d5348f40d1695a745470e1f23f43
b0b7133ed096f9b56fae91c874bd3ac0
d7558fdaf5f1105bb213282b707729a3
d8f35f4eb7872b2dab0692e315382fb0
f5c86af36162f13a64f54f6dc9587c06"""

prints = []
for line in blob.split():
  l = line.strip()
  lst = []
  while l:
    lst.append(l[:2])
    l = l[2:]
  prints.append(":".join(lst))


allprints = '("' + '","'.join(prints) + '")'
print allprints

for p in prints:
  q = 'SELECT * FROM acerts WHERE fingerprint like "%s" or `Serial Number` like "%s"' % (p, p)
  print q
  dbc.execute(q)
  print dbc.fetchall()

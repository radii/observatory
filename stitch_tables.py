#!/usr/bin/env python

import MySQLdb
import sys, getopt, os.path
import column_counter 

# Fields we don't use VARCHARs for, to save space:

EXCEPTIONS = ["x509v3 extensions:x509v3 crl distribution points"]
class TableStitcher:

  def __init__(self,tables, load_invalid):
    self.valid_only = not load_invalid

    from dbconnect import dbconnect
    self.db, self.dbc = dbconnect()
    self.tables = tables
    self.calc_max_widths()
    self.calc_total_rows()

  def calc_max_widths(self):
    "Find the max. width for every column type that exists in any of the tables"
    self.max_widths = {}
    self.nice_names = {}  # not lower cased
    for t in self.tables:
      print "measuring", t
      for column, width in column_counter.column_widths(t,self.valid_only):
        cname = column.lower()
        self.nice_names[cname] = column
        previously = self.max_widths.setdefault(cname,0)
        if width > previously:
          self.max_widths[cname] = width
    self.total_width = sum(self.max_widths.values())
    for e in EXCEPTIONS:
      try:    self.total_width -= self.max_widths[e]
      except: pass         # only happens with small portions of the dataset
    print self.max_widths

  def print_summary(self):
    column_counter.print_column_table(self.max_widths.items())
    print len(self.max_widths.keys()), "columns"
    print self.total_rows, "rows"
    print "total width", self.total_width

  def calc_total_rows(self):
    total = 0
    for t in self.tables:
      q = "select count(*) from %s" %t
      self.dbc.execute(q)
      count = self.dbc.fetchone()[0]
      total += count
    self.total_rows = total

  def define_new_table(self, new_t, create_only=False):
    "Create a new table named new_t that can hold the union of all our tables."
    assert self.total_width < 65535, "Total column width too wide for MySQL"
    q = "DROP TABLE IF EXISTS %s" % new_t
    print q
    self.dbc.execute(q)
    sorted_columns = self.max_widths.items()
    sorted_columns.sort()
    column_description = []
    for col, maxwidth in sorted_columns:
      # Some columns only exist for invalid certs
      if maxwidth > 0:
        column_description.append("`%s` %s" \
                        % (self.nice_names[col], self.col_type(col, maxwidth)))
    # if we create this later, we don't want auto-incrementation
    if create_only: column_description.append("certid INTEGER")
    else: column_description.append("certid INTEGER AUTO_INCREMENT")
    column_description.append("PRIMARY KEY(`certid`)")
    column_description.append("UNIQUE KEY(fingerprint)")
    q = "CREATE TABLE %s (\n  " % new_t
    q += ",\n  ".join(column_description)
    q += "\n)"
    print q
    self.dbc.execute(q)

  def col_type(self, cname, maxwidth):
    "What type should the new master table use for the column cname?"
    if cname == "fetchtime":
      return "INTEGER"
    elif cname == "fingerprint":
      return "CHAR(80) NOT NULL"
    elif cname == "valid":
      return "BOOL"
    elif cname == "certid":
      return "INTEGER AUTO_INCREMENT"
    elif cname == "RSA_Modulus_Bits":
      return "INTEGER"
    elif cname in EXCEPTIONS:
      return "BLOB"  # necessary for column widths
    else:
      return "VARCHAR(%d)" % maxwidth

  def stitch(self, new_t, extra_criteria=""):
    "Actually merge all of the old tables into the new one!"
    for t in self.tables:
      self.dbc.execute("DESC " + t)
      columns = ["`"+c[0]+"`" for c in self.dbc.fetchall() \
                 if self.max_widths[c[0].lower()] > 0]       # avoid invalid-only
                                                             # columns
      targets =  ", ".join(columns) 

      q = "INSERT IGNORE INTO %s(%s) SELECT %s FROM %s " \
          % (new_t, targets, targets, t)
      if self.valid_only: 
        q += 'WHERE valid '
      elif extra_criteria != None and len(extra_criteria) != 0:
        q += "WHERE "
      else:
        q += "WHERE Fingerprint is not null "
      q += extra_criteria
      print q
      self.dbc.execute(q)

    self.create_indicies(new_t)
  def create_indicies(self, new_t):
    #q = "CREATE INDEX p ON %s(path)" % new_t   # not useful if fingerprints are unique
    #self.dbc.execute(q)
    #disabling index on Subject, filed is always too long for mysql
    q = "CREATE INDEX s ON %s(Subject) USING HASH" % new_t
    print q
    self.dbc.execute(q)
    q = "CREATE INDEX i ON %s(Issuer) USING HASH" % new_t
    print q
    self.dbc.execute(q)
    #q = "CREATE INDEX v ON %s(valid)" % new_t
    #self.dbc.execute(q)
    q = "CREATE INDEX ku ON %s(`X509v3 extensions:X509v3 Key Usage`)" % new_t
    print q
    self.dbc.execute(q)
    q = "CREATE INDEX ca ON %s(`X509v3 extensions:X509v3 Basic Constraints:CA`)" % new_t
    print q
    self.dbc.execute(q)
    q = "CREATE INDEX akid ON %s(`X509v3 extensions:X509v3 Authority Key Identifier:keyid`)" % new_t
    print q
    self.dbc.execute(q)
    q = "CREATE INDEX skid ON %s(`X509v3 extensions:X509v3 Subject Key Identifier`)" % new_t
    print q
    self.dbc.execute(q)

  seen_create = """
  CREATE TABLE seen( 
    ip varchar(15), 
    fingerprint varchar(80),
    fetchtime integer, 
    path varchar(100), 
    valid varchar(1000))"""
  def make_seen_table(self, seen_table):
    # new_t is the table we just created
    
    q = "drop table if exists %s" % seen_table
    print q
    self.dbc.execute(q)
    print self.seen_create
    self.dbc.execute(self.seen_create)
    for t in self.tables:
      q = "insert into %s " %seen_table
      q += "select ip, fingerprint, fetchtime, path, valid from %s" % t
      print q
      self.dbc.execute(q)
    q = "create index p on seen(path)"
    print q
    self.dbc.execute(q)


def tname(argument):
  # Silly code to extract tablename from a cl argument that might be /dir/tablename/
  clue = "sslscanner"
  p = argument.split(os.path.sep)
  p = filter( lambda c:c, p) # remove a trailing /, effectively
  name = p[-1]
  if clue in name:
    name = name[len(clue):]
    name = "certs" + name
  return name

def main():
  try:
    args = sys.argv[1:]
    opts, remainder = getopt.getopt(args, "", \
                ["allcerts", "into=","seen=", "empty"])
  except :
    print "Usage: stitch_tables [--into <merged table>] <table1> [table2 ...] [--emppty]"
    print "                     [--seen <new seen table] "
    print "                     [--allcerts]"
    print 
    print "tables can be sslscanner paths; we will adjust them"
    print "  --allcerts : include invalid certs (default: valid certs only)"
    print ""
    print '  --seen     : build the "seen" table recording IP/certid/fetchtime'
    print ""
    print "  --empty    : create a valid certs table with the correct fields"
    print "               for the input dataset but do not fill it (so that"
    print "               cert ids can be synced from a table of all certs)"

    sys.exit(0)

  merge_into = seen_table = ""
  invalid_too = False # invalid certs not included by default
  create_only = False # create valid_certs but do not populate it
  for option, value in opts:
    if option == "--into":
      merge_into = value
    if option == "--empty":
      create_only = True
      print "Creating only..."
    elif option == "--seen":
      seen_table = value
    elif option == "--allcerts":
      invalid_too = True
  if create_only: assert merge_into
  tables = map(tname, remainder)
  print "Tables:", tables
  s = TableStitcher(tables, invalid_too)
  s.print_summary()
  if merge_into:
    s.define_new_table(merge_into,create_only)
    if not create_only: s.stitch(merge_into)
  if seen_table:
    s.make_seen_table(seen_table)

if __name__ == "__main__":
  main()

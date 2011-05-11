#!/usr/bin/env python

import string
import MySQLdb
import _mysql_exceptions
import sys
import openssl_dump
from glob import glob
import os,os.path
#import pdb # debug support
import re

try:
  import psyco # if available
  psyco.profile()
except:
  sys.stderr.write("PSYCO NOT AVAILABLE\n")

# configurables
DEFAULT_TABLE = "certs"

# other constants 

USAGE = """
python hackparse.py [--table NAME] [--readable] [--create] <dirs>

Args: 
\t--table    uses provided table NAME for data
\t--readable do no parsing; instead, make the "readable" table of
\t           prettyprinted certificates
\t--create   drops the table if it exists and creates it a new
\t           a list of directories (if none specified defaults to *.x.x.x)
\t<dirs>     directories to scan for .results files
"""

parse_roots = False
make_readable_table = False
allhex = ":" + string.hexdigits
tablename = DEFAULT_TABLE
allfields = []

# A hack parser for the output of 
# openssl x509 -text -in <file>
# Intended to allow us to try building some sample database tables...


neg = "(Negative)"
def hexline(line):
  if line[:len(neg)] == neg:
    line = line[len(neg):]
  return filter(lambda c : c not in allhex, line.strip()) == ""

# Parse the output of the openssl x509 command in a somewhat hackish manner

def makelinestruct(line):
  # XXX This tab replacement seemed to be necessary for 130.149.160.152.results
  # (!!!)
  l = line.replace("\t","        ")
  stripped = l.lstrip()
  indent = len(l) - len(stripped)
  return (indent, line, stripped)

def bottom_indent(lines, lineno):
  # Returns:
  #     -1 definitely not the bottom
  #      0 equivalent to next line
  #      1 deeper than next line
  base_indent = lines[lineno][0]
  for n in range(lineno+1,len(lines)):
    indent = lines[n][0]
    if indent > base_indent:
      return -1
    elif indent < base_indent:
      return 1
    else:
      return 0

def unknown_extension(line):
  # Return true if this looks like an unknown x509v3 extension
  if "." in line:
    l = line.split(".")
    l = "".join(l)
    if filter(lambda c:c not in string.digits, l) == "":
      return True
  return False

def probably_splittable(line):
  """
  Return True if we think this line has a 
  fieldname: value
  sort of structure; we do still get this wrong fairly often and the 
  recursions in process_results() are one way of coping with that.
  """
  if ":" in line:
    delim = line.find(":")
    if 0 < line.find("http:") < delim:
      return False
    if 0 < line.find("https:") < delim:
      return False
    return True
  else:
    return False

def hacky_parse(cstring):
  "cstring -- a string produced by openssl x509 -text"
  #print "cs:", cstring
  lines = [makelinestruct(l) for l in cstring.split("\n")]
  prev_indent = -1 
  results = {}
  value = ""
  # a list of nodes in the parse tree that we're below
  struct = []
  struct_indents = []
  last_result_struct = []    # The last plausible result struct, in case we need
                             # to backtrack.
  unknown = False              # About to encounter an unknown x509v3 field
  for n,(i,line,lstripped) in enumerate(lines):
    l = line.strip()
    if not l:
      # don't get confused by blank lines
      continue
    #print "%d,%d: %r" %(n,i,line)

    # diabolical, horrid hack to handle \n in a value
    if n > 0 and i < 4 and l != "Certificate:":
      if i !=0:
        print "WARNING, very weird line", l
      value += l
      if bottom > 0:
        process_results(results, struct, value)
        last_result_struct = struct
        value = ""
      continue

    bottom = bottom_indent(lines,n)
    if i < prev_indent:
      # We've climbed back up the indent tree; chop off the branch we've left
      try:
        chop = struct_indents.index(i)
      except:
        raise
      #print "before chop", chop, struct
      last_result_struct = struct
      struct = struct[:chop]
      struct_indents = struct_indents[:chop]
      #print "after chop", struct

    if bottom >= 0:
      #print "+"
      if not hexline(l):
        ps = probably_splittable(l)
        if ps and not unknown:
          delim=l.find(":")
          struct.append(l[:delim])
          value = l[delim+1:]
        else:
          value = l
          #assert bottom !=0, "beaten by\n" + l
          if bottom == 0:
            # This is not supposed to happen, but it does in some weird cases
            # that require special treatment.
            print "Bizarre Special Case:"
            print cstring
            print "Winding back to", last_result_struct
            if "Netscape Comment" in last_result_struct:
              # These can be indendented in profoundly confusing ways
              struct = last_result_struct
            elif l == "keyid":
              # openssl x509 does not put a ":" after keyid if the keyid is blank
              struct.append(l)
              value = ""
              ps = True # ket the keyid popped again
            else:
              raise ValueError, "beaten by\n" + l

        process_results(results, struct, value)
        last_result_struct = struct
        value = ""
        if ps and not unknown:
          last_result_struct = struct[:]  # Unlike other struct changes, .pop()
                                          # occurs in place
          struct.pop()
        unknown = False
      else:            # hexline
        value += l
        if bottom > 0:
          #print "bottom adding", struct
          process_results(results, struct, value)
          value = ""

    else:              # bottom < 0
      enstruct(struct,struct_indents,l,i)
      if unknown_extension(line):
        unknown = True
      #print "struct now", struct

    prev_indent = i

  return results

pol = "Policy"
def enstruct(struct, struct_indents, line, i):
  """
  Work out which parts of a line should be appeneded to the field name struct
  """
  #print "enstructing", line, struct
  try:
    if line[:len(pol)] == pol:
      #print "pol pruning", line
      struct.append(pol)
      struct.append(line[len(pol)+1:])
      struct.indents.extend([i, i+len(pol)])
      return
  except:
    pass
  if line[-1] == ":":
    line = line[:-1]
  struct.append(line)
  struct_indents.append(i)

        
def shrink_field(field, value):
  # Shrink a field to less than 64 characters to keep mysql happy
  # raise an excepiton if that was not possible
  while len(field) > 64:
    if ":" not in field:
      print "shrinkerror inserting", field, " === ", value
      raise ValueError, "cannot shrink " + field

    field = field[field.find(":") + 1:].strip()
  return field

# We do not want database columns created for any nodes below these in the
# tree; if anyone cares about subtypes of these fields they can handle that
# with their mysql queries

splitters = ["Policy", "Subject Alternative Name", 
             "X509v3 Subject Alternative Name",
             "X509v3 Subject Alternative Name: critical",
             "X509v3 Subject Directory Attributes",
             "X509v3 CRL Distribution Points",
             "X509v3 Issuer Alternative Name",
             "X509v3 Name Constraints",            # not sure which...
             "X509v3 Name Constraints:Permitted",
             "Netscape Base Url",
             "Netscape Comment",
             "Netscape Revocation Url",
             "Netscape Renewal Url",
             "Netscape CA Revocation Url",
             "Netscape CA Policy Url",
             "X509v3 Certificate Policies",
             "X509v3 Freshest CRL",
             "X509v3 Name Constraints"
             ]

def process_results(results, field_struct, value, recurse=False):
  """ tracking field structure, attempt to add value, recursing if needed
      and altering the table to add fields not yet seen. This potentially
      updates the module level state of the list of defined fields too.
      Hooks for rewriting field names and adding additional fields also.
      This is a bit hirsute.
  """
  # field_struct is something like:
  # ["Certificate","Data","Subject Public Key Info","RSA Public Key","Modulus..
  # (1024 bit)"]
  #if recurse: print "(RECURSIVE)"
  #print "Processing", field_struct,":", `value`

  f = field_struct # f is the mutable reference used throughout
  v = value                # leave value untouched as it was passed to us
  # Chop off leading Certificate:Data, because they're too long...
  if f[0] == "Certificate":
    f = f[1:]
  if f[0] == "Data":
    f = f[1:]

  for s in splitters:
    if s in f:
      pos = f.index(s) + 1
      if pos < len(f):
        # We're actually doing some splitting
        v= ":".join(f[pos:]) + "===" + value
        f = f[:pos] 
      break # This is an hack that allows both "Policy" and "X509v3 Certificate 
            # Policies" to be splitters, with the first operating precedentially

  if "X509v3 extensions" in f:
    pos = f.index("X509v3 extensions") + 1
    if unknown_extension(f[pos]):
      f = f[:pos] + ["Unknown"]
      v = ":".join(f[pos:]) + "==" + value
    else:
      #print f[pos], "not unknown"
      pass
  field = ":".join(f)
  field = field.strip()
  try:
    field = shrink_field(field, v)
  except:
    if not recurse:
      process_results(results, field_struct[:-1], field_struct[-1] +":"+ value,1)
      return
    else: raise

  if field != gdb.escape_string(field):
    print "UNSAFE field", field
    if not recurse:
      # One theory here is that we've probably confused the value and field;
      # try to correct that
      process_results(results, field_struct[:-1], field_struct[-1] +":"+ value,1)
      return
    else:
      # OKay, the the theory failed
      raise Exception("Terminally unsafe field " + field)
  
  field, v, extra = rewrite(field, v)
  add_result(results, field, v)
  if extra: 
    add_result(results, extra[0], extra[1])

def add_result(results, field, value):
  "Insert field:value into results"
  if field not in allfields: 
    # We might not have this column yet, so let's try to create it
    add_field(field)

  if field not in results:
    results[field] = value
  else:
    results[field] += " ANDALSO " + value
  

def add_field(fieldname):
  "Adds a field, cleaning it up, altering the DB and appending to allfields"
  allfields.append(fieldname)
  q = "ALTER TABLE %s ADD COLUMN `%s` TEXT" % (gdb.escape_string(tablename), \
      gdb.escape_string(fieldname.strip()))
  print q
  try:
    gdbc.execute(q)
  except _mysql_exceptions.OperationalError, e:
    # if two instances of this to run at once 
    if "Duplicate column name" in `e`:
      # Another instance already created this column
      return
    raise e

class RewriteRule:
  # These objects rewrite field names
  def __init__(self, target, newfield, value_pre_fnc, toAdd = None, value_func = None):
    """
    target: a regexp defining which fields we're after
    newfield: a regexp target defining what the field should become
    value_pre_fnc: a function, passed the match giving the text that
      should be prepended to the values in columns affected by this rule.
    toAdd: optional field to add when this rule hits
    value_function: function passed match for computing value for toAdd field
    """
    self.target = re.compile(target)
    self.newfield = newfield
    self.value_pre_func = value_pre_fnc
    self.field_to_add = toAdd
    self.fval_func = value_func

  def match(self, fieldname):
    return self.target.match(fieldname)

  def apply(self, fieldname):
    "Returns the (possibly) rewritten fieldname and text to prepend to the value"
    newfieldname = self.target.sub(self.newfield, fieldname)
    e = None
    if self.field_to_add and self.fval_func:
      e = (self.field_to_add, self.fval_func(self.target.match(fieldname)))
    return (newfieldname, self.value_pre_func(self.target.match(fieldname)), e)

rewrite_rules = [
  RewriteRule(
    "X509v3 Basic Constraints: critical:CA", 
    "X509v3 extensions:X509v3 Basic Constraints:CA",
    lambda match: "(critical) "
  ),

  RewriteRule(
    "(.*): critical(.*)", 
    r"\1\2",
    lambda match: "(critical) "
  ),
  RewriteRule(
    "RSA Public Key: \(([0-9]+) bit\):Modulus \([0-9]+ bit\)", 
    "RSA Public Key:Modulus", 
    lambda match: "", # no longer does anything, redundant by RSA_Modulus_Bits
    "RSA_Modulus_Bits",
    lambda match: match.group(1)
  ),
  RewriteRule(
    "Signature Algorithm: (.+)", 
    "Signature", 
    lambda match: "", # no longer does anything, as this data is now redundant
  ),
  RewriteRule(
    "Subject Public Key Info:RSA Public Key: \(([0-9]+) bit\):Exponent",
    "Subject Public Key Info:RSA Public Key:Exponent",
    lambda match: "" # also omitted, was redundant with RSA_Modulus_Bits
  )
]

def rewrite(field, value):
  "Apply the RewriteRules."
  for rule in rewrite_rules:
    if rule.match(field):
      newfield, prepend, extra = rule.apply(field)
      return newfield, prepend + value, extra
  return field, value, None

eg = """Certificate:
    Data:
        Version: 1 (0x0)
        Serial Number: 0 (0x0)
        Signature Algorithm: md5WithRSAEncryption
        Issuer: C=CA, ST=Quebec, L=Gatineau, O=Axentraserver Default Certificate 38DA2D63, CN=localdomain/emailAddress=support@axentra.com
        Validity
            Not Before: Apr 20 13:09:57 2007 GMT
            Not After : Apr 19 13:09:57 2017 GMT
        Subject: C=CA, ST=Quebec, L=Gatineau, O=Axentraserver Default Certificate 38DA2D63, CN=localdomain/emailAddress=support@axentra.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (1024 bit)
                Modulus (1024 bit):
                    00:bf:42:07:bd:ea:73:a3:3e:90:e8:21:08:40:c6:
                    6c:38:0a:fd:60:b9:76:20:af:97:07:34:fc:ea:61:
                    8f:f6:64:bb:cc:8d:b8:22:88:b1:20:41:9d:e7:45:
                    d1:f1:e7:40:83:ae:eb:42:52:43:db:9c:1c:52:4b:
                    15:5a:fe:29:c4:a6:14:29:15:af:07:1e:76:15:f3:
                    2b:b9:e9:3c:6d:ba:e9:e0:19:9e:5a:0c:c3:43:62:
                    ad:88:44:c2:29:ae:e9:ab:10:47:60:62:b9:12:f6:
                    cb:fe:8f:2e:f9:a1:df:d3:a9:64:67:b1:0f:d1:91:
                    b7:b2:91:6f:9f:d9:d5:de:6f
                Exponent: 65537 (0x10001)
    Signature Algorithm: md5WithRSAEncryption
        56:d1:9f:e4:d3:e5:c7:e4:c1:94:8c:8f:1a:cb:43:26:bc:91:
        8e:4e:7a:a4:6a:2c:e2:39:80:c4:21:e8:84:8b:40:4b:4d:6f:
        01:c1:ae:2e:1b:57:33:3b:6f:39:73:0a:8c:90:e1:ab:fe:85:
        eb:8f:85:df:6a:4e:9c:44:f2:1f:14:55:3c:36:68:b1:62:ef:
        90:c8:7d:91:6b:03:2c:a5:2a:19:57:fe:d6:8c:11:c9:df:9a:
        f3:8c:b2:37:1e:c5:82:28:61:cb:35:a5:5b:39:af:26:5a:83:
        21:1e:4b:25:f1:0d:14:72:c9:e3:91:85:e7:c2:7e:7d:6a:53:
        79:e0
"""

eg2 = """
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            8f:b4:10:48:f5:52:a3:7c:ed:66:8e:0a:bc:b4:ba:a2
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: C=US, ST=UT, L=Salt Lake City, O=The USERTRUST Network, OU=http://www.usertrust.com, CN=UTN-USERFirst-Hardware
        Validity
            Not Before: Mar  8 00:00:00 2010 GMT
            Not After : Mar  8 23:59:59 2011 GMT
        Subject: C=RO/postalCode=022141, ST=Bucharest, L=Bucharest/street=B-dul Chisinau nr.1, Subsol, O=Pro Link SRL, OU=IT, OU=Provided by directNIC, OU=Direct NIC Pro SSL, CN=miraculoussalesman.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (1024 bit)
                Modulus (1024 bit):
                    00:cb:ab:03:a0:e5:66:dc:88:83:d9:98:a8:86:67:
                    37:d0:08:43:87:4d:a1:18:f0:23:e1:d2:5c:e4:81:
                    b8:71:66:80:b8:54:2f:06:1f:e3:ba:79:67:63:29:
                    4f:0f:35:0c:a8:fa:32:95:39:92:24:2f:c4:41:ab:
                    62:3e:2c:c9:d7:2b:bc:be:92:42:3f:69:27:8f:8c:
                    80:4b:b6:be:04:8a:57:8e:0a:f1:18:4e:1d:6b:23:
                    8b:1d:b9:20:ca:67:7a:a6:af:ad:59:bb:98:70:f5:
                    c1:df:de:ba:45:b4:94:e2:2c:81:ba:7a:88:99:7e:
                    9f:51:d0:73:de:26:3b:dd:0f
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Authority Key Identifier: 
                keyid:A1:72:5F:26:1B:28:98:43:95:5D:07:37:D5:85:96:9D:4B:D2:C3:45

            X509v3 Subject Key Identifier: 
                B1:57:A6:20:FB:FC:60:94:E1:2D:65:8A:06:30:43:31:70:A1:21:56
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Certificate Policies: 
                Policy: 1.3.6.1.4.1.6449.1.2.1.3.4
                  CPS: https://secure.comodo.net/CPS

            X509v3 CRL Distribution Points: 
                URI:http://crl.comodoca.com/UTN-USERFirst-Hardware.crl
                URI:http://crl.comodo.net/UTN-USERFirst-Hardware.crl

            Authority Information Access: 
                CA Issuers - URI:http://crt.comodoca.com/UTNAddTrustServerCA.crt
                OCSP - URI:http://ocsp.comodoca.com

            X509v3 Subject Alternative Name: 
                DNS:miraculoussalesman.com, DNS:www.miraculoussalesman.com
    Signature Algorithm: sha1WithRSAEncryption
        1f:1f:e4:40:5c:99:b6:0a:d6:ee:9b:3a:41:52:b1:a7:f3:fb:
        f9:72:b8:b3:71:0f:fc:81:d4:90:7f:ef:a5:e0:63:64:19:72:
        17:bb:ee:2a:10:1b:99:17:89:c7:8c:d1:53:09:9a:6a:cd:14:
        90:58:b7:e3:6c:75:2d:83:49:7e:e7:32:9b:45:33:1e:e5:de:
        b7:7f:c9:1b:c8:37:b0:7b:21:3e:7f:ce:04:13:82:a8:a0:7d:
        19:88:4d:81:fe:94:69:0b:63:4d:fd:29:09:32:c9:80:ff:42:
        53:9b:d7:64:41:e9:35:e6:b5:d6:cb:dc:a6:cb:39:9c:aa:b0:
        23:a5:28:dd:2a:1c:bd:f6:d2:2c:af:a2:a6:c3:1f:13:e4:85:
        72:e1:4b:ea:1c:3f:21:1b:4f:1c:f4:f2:3b:f0:05:eb:b0:94:
        0b:3b:38:ae:e2:4e:23:54:61:24:a2:62:d5:75:ef:dc:6b:cf:
        90:76:97:8f:1f:cf:fb:53:f5:d0:3e:3f:15:03:92:c1:81:11:
        7d:b4:49:29:f5:a2:16:f3:c8:cb:8b:95:e0:8c:f5:21:c2:f4:
        21:50:e6:b0:8f:18:4f:5f:13:49:31:cd:9e:cf:a8:0e:5d:a1:
        3a:dc:45:07:57:e2:13:11:92:b9:4e:e4:a9:ed:a7:b0:42:8b:
        4b:fd:49:2d
"""

def add_cert_to_db(path, validities, x509_parsed_certchain, fprints):
  for i, parsed_cert in enumerate(x509_parsed_certchain):
    print "parsing", path
    try:
      fields = hacky_parse(parsed_cert)
    except:
      print "Error parsing", path + "\n" + parsed_cert
      raise
    fields['path'] = path
    moz_valid, ms_valid = validities[i]
    if ("Yes" in validities[i]): valid = 1 
    else: valid = 0
    fields['moz_valid'] = moz_valid
    fields['ms_valid'] = ms_valid
    if len(fprints[i]): fields['fingerprint'] = fprints[i]
    fields['ip'] = path[path.rindex('/') +1:-8] # linux pathsep dependency
    q = "INSERT INTO %s SET " % gdb.escape_string(tablename)
    q += "`fetchtime`=%.0f ,\n" % os.path.getmtime(path)
    q += "valid=%r ,\n" % valid
    for (f,v) in fields.items():
      q += "`%s`='%s' ,\n" % (gdb.escape_string(f), gdb.escape_string(v))
    q = q[:-2]
    gdbc.execute(q)

def process_args():
  # XXX YUCK USE GETOPT
  global tablename, parse_roots, make_readable_table, create
  args = sys.argv
  create = False
  if "--table" in args:
    pos = args.index("--table")
    tablename=args[pos + 1]
    print "tablename is now", tablename
    args=args[:pos] + args[pos+2:]
    print "args are now", args

  if "--roots" in args:
    args=filter(lambda a: a!="--roots", args)
    parse_roots=True
  if "--create" in args:
    args=filter(lambda a: a!="--create", args)
    create = True
  if "--readable" in args:
    args=filter(lambda a: a!="--readable", args)
    make_readable_table=True
  # The if we're doing --readable, --create refers to that table
  if create and not make_readable_table:
    create_table()
  return args


from dbconnect import dbconnect
gdb, gdbc = dbconnect()
def db_from_results(dirs):
  print "Targetting", dirs
  for d in dirs:
    for path, validities, x509_certchain, fprints in openssl_dump.dumpByDir(d):
      add_cert_to_db(path, validities, x509_certchain, fprints)

  make_indicies()

  print "Exiting correctly..."
 
def make_indicies(tablename):
  # Make some indicies
  to_index = ["valid"]
  # use hashes to index these:
  index_h = ["Subject","Issuer",\
             "X509v3 extensions:X509v3 Subject Key Identifier",\
             "X509v3 extensions:X509v3 Authority Key Identifier:keyid" ]
  for i,field in enumerate(to_index):
    q = "CREATE INDEX i%d ON %s(`%s`)" % (i, tablename, field)
    print q
    gdbc.execute(q)
  for i,field in enumerate(index_h):
    q = "CREATE INDEX h%d ON %s(`%s` (10000)) USING HASH" % (i, tablename, field)
    print q
    gdbc.execute(q)


def db_from_roots():
  # This is a terrible hack to work out whether each cert is a MS root, Moz
  # root, or both by remembering what paths we've seen it at
  roots = {}
  for path, x509_rootcert, fprint in openssl_dump.dumpRootCAs():
    # represent each unique root cert as a dictionary
    entry = roots.setdefault(fprint,{})
    entry.setdefault("moz","No")
    entry.setdefault("ms","No")
    if "ms_xp_ca" in path:        entry["ms"]  = "Yes"
    else:                         entry["moz"] = "Yes"
    entry["cert"] = x509_rootcert
    entry["path"] = path

  for fprint, e in roots.items():
    add_cert_to_db(e["path"], [(e["moz"],e["ms"])], [e["cert"]], [fprint])

def mk_readable(dirs):
  # Make a table containing prettyprinted readable certs, rather than
  # parsing them
  if create:
    q = "DROP TABLE IF EXISTS readable"
    print q
    gdbc.execute(q)
    q = "CREATE TABLE readable (fingerprint CHAR(80), cert text, unique(fingerprint))"
    print q
    gdbc.execute(q)
  for d in dirs:
    for path, x509_certchain, fprints in openssl_dump.dumpByDirNoValidate(d):
      q = ['("%s", "%s")' % tuple(map(gdb.escape_string, fc)) \
                            for fc in zip(fprints,x509_certchain)]
      if not q: continue
      # XXX TODO: BY REMOVING THE IGNORE AND ADDING SOME ASSERTION CODE, THIS WOULD
      # BE A GOOD PLACE TO CHECK FOR SHA1 COLLISIONS!
      # (but watch out because of the batched nature of the insertion)
      q = 'INSERT IGNORE INTO readable VALUES ' + ",".join(q)
      gdbc.execute(q)

 

  


def create_table():
  # Create a fresh exciting certs table for us to play with
  print "tablename is", tablename
  gdbc.execute("DROP TABLE IF EXISTS %s" % gdb.escape_string(tablename))
  ctable = "CREATE TABLE `%s` (\n" % gdb.escape_string(tablename)
  ctable += "`id` INTEGER AUTO_INCREMENT,\n"
  ctable += "PRIMARY KEY(`id`),\n"
  ctable += "path VARCHAR(512),\n"
  ctable += "valid BOOL,\n"
  ctable += "moz_valid TEXT,\n"
  ctable += "ms_valid TEXT,\n"
  ctable += "fingerprint VARCHAR(256),\n"
  ctable += "ip VARCHAR(16),\n"
  ctable += "fetchtime INTEGER,\n"
    
  #for field in allfields:
  #  ctable += "`%s` VARCHAR(1023) DEFAULT '',\n" % gdb.escape_string(field.strip())
  ctable = ctable[:-2] + ")" # chop off trailing comma
  print "ctable:\n" + ctable
  gdbc.execute(ctable)
if __name__ == "__main__":
  if len(sys.argv) < 2:
    print USAGE
    sys.exit(1)
  try:
    dirs = process_args()[1:]
  except:
    dirs = glob("*.x.x.x")

  if make_readable_table:
    mk_readable(dirs)
    sys.exit(0)

  if parse_roots:
    db_from_roots()
  else:
    db_from_results(dirs)
#print hacky_parse(eg2)

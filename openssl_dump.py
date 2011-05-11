#!/usr/bin/env python
"""
Gives you the file name and runs openssl, returning the array of certificate 
results for every ssl certificate conversation (.result file) under the passed 
in directory.
"""

import os, subprocess, sys, os.path
sys.path.append("scan")
from TLSConstructs import *
import traceback
import tempfile
from subprocess import PIPE
from glob import glob

USAGE = "pass the path to the directory to start looking for .results files."
OPENSSL_ARGS = ['openssl', 'x509', '-fingerprint', '-noout', '-text']
DER_ARGS = ['openssl', 'x509', '-fingerprint', '-inform', 'DER', '-noout', '-text']

# would be better to use a relative path to mozilla_CAs, but we don't know how
# to get there...
moz_trusted_ca_path = ['/tmp/cas','/home/jesse/sslscanner/mozilla_CAs',
                       'mozilla_CAs','./mozilla_CAs/']
ms_trusted_ca_path = ['/home/pde/sslscanner/microsoft_CAs',
                      '/home/pde/eff/ssl/survey/scanner3/microsoft_CAs',
                      './microsoft_CAs/']
all_trusted_ca_path = ['/home/pde/sslscanner/allcerts',
                      '/home/pde/eff/ssl/survey/scanner3/allcerts',
                      './allcerts/']

moz_ca_store = filter(os.path.isdir, moz_trusted_ca_path)[0]
ms_ca_store  = filter(os.path.isdir, ms_trusted_ca_path)[0]
all_ca_store  = filter(os.path.isdir, all_trusted_ca_path)[0]

MOZ_VERIFY_ARGS = ['openssl', 'verify', '-CApath', moz_ca_store]
MS_VERIFY_ARGS = ['openssl', 'verify', '-CApath', ms_ca_store]
ALL_VERIFY_ARGS = ['openssl', 'verify', '-CApath', all_ca_store]
SERVER_VRFY = ['-purpose', 'sslserver']

def check_for_openssl_attime():
  "Test if the available copy of openssl includes our -attime patch"
  cmd = subprocess.Popen(['openssl', 'verify', '-help'], stdout=PIPE, stderr=PIPE)
  out, err = cmd.communicate()
  avail = "attime" in err
  if not avail:
    w = sys.stderr.write
    w('NOTE: the -attime argument to "openssl verify" is not available.  Without that\n')
    w("      patch applied, certificate expiry is evaluated as of NOW, not when the\n")
    w("      certs were collected.  The patch is in openssl-patches/.\n")
  return avail

ATTIME_AVAILABLE = check_for_openssl_attime()

def dataToCerts(data):
  recs = TLSRecord.parse(data)
  certs = []
  for rec in recs:
    if rec.ContentType == 'handshake':
      handshake_messages = Handshake.parse(rec.data)
      for hand_msg in handshake_messages:
        if hand_msg.msg_type == 'certificate':
          cert_msg = Certificate.parse(hand_msg.body)
          data_read = 0
          while data_read < cert_msg.list_length:
            cert = ASNCert.parse(cert_msg.list_data[data_read:])
            data_read += cert.cert_length + 3
            certs.append(cert)
  return certs

ssc = "self signed certificate"
def verifyOneCert(cert, rest_of_chain, cmd, extra_args, retries=3, verbose=False):
  cmdline = cmd + extra_args
  if rest_of_chain:
    # In an extremely confusing manner not documented in its man page,
    # openssl's verify command appears to require that all intermediate certs
    # be placed in an "untrusted" cert file, while the cert to actually be
    # checked goes in separately (or in our case, by stdin)
    tmp,tmp_path = tempfile.mkstemp(".certs")
    os.write(tmp,"".join(rest_of_chain))
    os.fsync(tmp)
    cmdline += ["-untrusted", tmp_path]
  try:
    if verbose: print cmdline
    proc = subprocess.Popen(cmdline, stdin=PIPE, stdout=PIPE)
    std_out, std_err = proc.communicate(cert)
  except:
    if retries == 0:
      print "Catastrophic failure to verify\n" + "".join([cert] + rest_of_chain)
      exit(1)
    return verifyOneCert(cert, rest_of_chain, cmd, extra_args, retries -1)
  finally:
    if rest_of_chain: 
      os.close(tmp)
      os.unlink(tmp_path)

  lines = std_out.strip().split("\n")
  if len(lines) == 1 and lines[0] == "stdin: OK" and not std_err:
    verified = "Yes"
  elif ssc in std_out:
    verified = "self-signed:"
    verified += std_out[std_out.find(ssc)+len(ssc):].replace("\n"," ")
  else:
    verified = "No: " + `std_out` + `std_err`
  return verified


def verifyCertChain(list_of_pem_certs, cmd, validation_time = None):
  """Attempt to establish a measure of validity for each cert in a chain
     validation_time is a timestamp for use in testing expiration"""   
  if not list_of_pem_certs:
    return "NO CERTS?"
  results = []
  # Verifying each cert in a chain independently of the others is confusing
  # and poorly defined, but the approach here is to say, "would this be
  # valid, given all the others as initially untrusted intermediate certs?"

  # XXX between 0.9.8o and late-2010 CVS versions of openssl, the semantics of
  # -untrusted seems to have changed, and we may have to become stricter about
  # what we include in the untrusted cert list in the future.
  for i, cert in enumerate(list_of_pem_certs):
    c = cert.strip()
    rest = list_of_pem_certs[:i] + list_of_pem_certs[i+1:]
    extra_args = []
    if i == 0: extra_args += SERVER_VRFY
    if validation_time and ATTIME_AVAILABLE: 
      cmd = cmd[:] + ["-attime", "%d" % validation_time]
    results.append(verifyOneCert(c, rest, cmd, extra_args))
  return results

def enc(certificate):
  out = '-----BEGIN CERTIFICATE-----\n'
  out += certificate.cert.encode('base64')
  out += '-----END CERTIFICATE-----\n'
  return out

def readAndParseCert(certtext,in_namepath):
  """ Call openssl x509 on a cert to obtain a text represenation of its contents 
  and its fingeprrint """
  a = subprocess.Popen(OPENSSL_ARGS, stdin=PIPE, stdout=PIPE)
  text = a.communicate(certtext)[0]
  return opensslParseOneCert(text)

def opensslParseOneCert(text):
  "Split out from the above so that pem_hackparse can play with it"
  fp = ''
  # always SHA1, but allowing for other possible hashes with some fudge
  if " Fingerprint=" in text[:25]: # 25, fudges instead of 16 or startswith
    fp, _, text = text.partition('\n')
  else: 
    if text:
      print "WARNING: fingerprint_failure without load fail:", text
  return [text,fp]


def toOpensslText(in_name):
  "takes file name, returns pem certs, outputs & fingerprints list"
  pem_certs = []
  output_texts = []
  fingerprints = []
  try:
    f = open(in_name, 'rb')
    certs = dataToCerts(f.read())
    f.close()
    for count,certificate in enumerate(certs):
      try:
        out = enc(certificate)
        pem_certs.append(out)
      except:
        traceback.print_exc()
        print "error with certificate %d in %s" % (count, in_name)
        return None
      text,fp = readAndParseCert(out,in_name)
      fingerprints.append(fp)
      output_texts.append(text)
  except:
    print "Error attempting to process ", in_name, len(pem_certs)
  return [pem_certs, output_texts, fingerprints]

def dumpByDir(start = '.'):
  "returns a tuple: path for chain, validity, list of text output."
  for root, dirs, files in os.walk(start):
    for fn in files:
      if fn.endswith('.results'):
        path = os.path.join(root, fn)
        pem_certs, output_texts, fingerprints = toOpensslText(path)
        timestamp = os.path.getmtime(path)
        moz_verifications = verifyCertChain(pem_certs,MOZ_VERIFY_ARGS,timestamp)
        ms_verifications = verifyCertChain(pem_certs,MS_VERIFY_ARGS,timestamp)
        verifications = zip(moz_verifications, ms_verifications)
        yield (path, verifications, output_texts, fingerprints)

def dumpByDirNoValidate(start = '.'):
  """Similar to dumpByDir but faster, because it doesn't calculate/return 
     verifications"""
  for root, dirs, files in os.walk(start):
    for fn in files:
      if fn.endswith('.results'):
        path = os.path.join(root, fn)
        pem_certs, output_texts, fingerprints = toOpensslText(path)
        yield (path, output_texts, fingerprints)

def dumpRootCAs():
  "returns a tuple: path for cert, validity, list of text output."
  p = all_ca_store + os.path.sep 
  for f in glob(p + "*.crt") + glob(p + "*.pem"):
    fobj = open(f,"rb")
    cert = fobj.read()
    fobj.close()
    yield tuple([f] + readAndParseCert(cert,f))

if __name__ == "__main__":
  if len(sys.argv) < 2:
    print USAGE
  else:
    for path, validities, certs, fprints in dumpByDir(sys.argv[1]):
      if certs:
        #print path, repr(r)
        print path, "Verified?", validities
        for n, cert_text in enumerate(certs):
          print 3*"-", fprints[n]
          print cert_text
        print 80*"-"

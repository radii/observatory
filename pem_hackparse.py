#!/usr/bin/env python

# Like hackparse, but instead of recursively sucking in .results files from
# some directory, it reads PEM-encoded cert files from the command line
import hackparse
import openssl_dump as od
import sys
from subprocess import Popen, PIPE
MAGIC_ERROR= "unable to load certificate"
print od.MOZ_VERIFY_ARGS

def main():
  args = hackparse.process_args()
  for f in args[1:]:
    fobj = open(f, "rb")
    cert = fobj.read()
    fobj.close()
    print "Hackparsing " + f
    a = Popen(od.OPENSSL_ARGS, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    try: pcert, err = a.communicate(cert)
    except:     err = MAGIC_ERROR

    if err.startswith(MAGIC_ERROR):
      a = Popen(od.DER_ARGS, stdin=PIPE, stdout=PIPE, stderr=PIPE)
      try: 
        pcert, err = a.communicate(cert)
        t = '-----BEGIN CERTIFICATE-----\n'
        t += pcert.encode('base64')
        pcert = t + '-----END CERTIFICATE-----\n'
      except:
        sys.stderr.write("WHACKO ERROR on %s\n" %f)
        continue
        
      if err.startswith(MAGIC_ERROR):
        sys.stderr.write("failed to load: %s\n" % f)
        continue
     
    text, fp = od.opensslParseOneCert(pcert)
    moz_verifications = od.verifyCertChain([text], od.MOZ_VERIFY_ARGS)
    ms_verifications = od.verifyCertChain([text], od.MS_VERIFY_ARGS)
    verifications = zip(moz_verifications, ms_verifications)

    hackparse.add_cert_to_db(f, verifications, [text], [fp])
    print "SUCCESS ON", f

if __name__ == "__main__":
  main()


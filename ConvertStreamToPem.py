#!/usr/bin/env python

from scan.TLSConstructs import *
import os, sys, os.path
import traceback

USAGE = "Please pass in file stream file convert --> pem certs.\n"
out_dir = 'certs'
try:
  os.mkdir (out_dir)
except:
  pass

def convert(in_name):
  try:
    f = open(in_name, 'rb')
    data = f.read()
    f.close
    
    count = 0
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
    for certificate in certs:
      try:
        count = count + 1
        out = open("%s%s%s_%d.pem" % (out_dir, os.sep, os.path.basename(in_name), count), 'w')
        out.write('-----BEGIN CERTIFICATE-----\n')
        out.write(certificate.cert.encode('base64'))
        out.write('-----END CERTIFICATE-----\n')
      except:
        traceback.print_exc()
        print "error with certificate %d in %s" % (count, in_name)
  except:
    print "Error attempting to process", in_name

if __name__ == "__main__":
  if len(sys.argv) < 2:
    print USAGE
  else:
    convert(sys.argv[1])  

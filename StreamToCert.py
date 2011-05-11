#!/usr/bin/env python
from TLSConstructs import *
import sys

USAGE = "Please pass in the name of a file to convert.\n"

def convert(in_name):
  f = open(in_name, 'rb')
  data = f.read()
  f.close
  
  recs = TLSRecord.parse(data)
  certs = []
  for rec in recs:
    if rec.ContentType == 'handshake':
      hand_messages = Handshake.parse(rec.data)
      #print hand_msg.msg_type
      for hand_msg in hand_messages: 
      	if hand_msg.msg_type == 'certificate':
	        cert_msg = Certificate.parse(hand_msg.body)
	        data_read = 0
	        while data_read < cert_msg.list_length:
	          cert = ASNCert.parse(cert_msg.list_data[data_read:])
	          data_read += cert.cert_length + 3
	          certs.append(cert)
  for certificate in certs:
    print '-----BEGIN CERTIFICATE-----'
    print certificate.cert.encode('base64'),      
    print '-----END CERTIFICATE-----' 
  return ''

if __name__ == "__main__":
  if len(sys.argv) < 2:
    print USAGE
  else:
    convert(sys.argv[1])  

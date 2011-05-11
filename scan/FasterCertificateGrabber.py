#!/usr/bin/env python

import binascii, random, select, socket, time, errno, traceback, sys
import os, os.path
from TLSConstructs import *

DEBUG = False
MAX_WAIT = 30 # wait time for entire request
MAX_CONNECT_WAIT = 10 # wait time for an ACK
ALLOWED_ACTIVE = 500

WAIT_TIME = 1 # seconds to wait between checking for time outs


SSL_v2_CLIENT_HELLO = '8074010301004b000000200000390000380000350000160000130' +\
                      '0000a0700c000003300003200002f030080000005000004010080' +\
                      '00001500001200000906004000001400001100000800000604008' +\
                      '00000030200808837143117c92059979c246e6dc46c5a95d6f708' +\
                      '51bd0c2109225879138a1997'

TLS_v1_CLIENT_HELLO = '16030100c6010000c203014b4654587bed2a1c1cc132b07689ca6' +\
                      'b8c79ea9b279e4e45c7fe77c51ab33d632029eb2686d8f371320b' +\
                      'a1acb077e251916a1f751c0fec408c60d0d6ce854889310046c00' +\
                      'ac0140088008700390038c00fc00500840035c007c009c011c013' +\
                      '0045004400330032c00cc00ec002c0040096004100040005002fc' +\
                      '008c01200160013c00dc003feff000a0100003300000019001700' +\
                      '00147777772e69736563706172746e6572732e636f6d000a00080' +\
                      '006001700180019000b0002010000230000'

hello_msg = binascii.a2b_hex(SSL_v2_CLIENT_HELLO)

complete_certs = 0
partial_certs = 0

WSAEISCONN = 10056 # Weird Windows socket error
WSAEWOULDBLOCK = 10035 # Yeah

# STATES
CONNECTING = 0
CONNECTED = 1
DATA_SENT = 2
DONE = 3
DEAD = 4

class CertificateRequest:
  def __init__(self, hostname, portnum = 443):
    self.host = hostname
    self.port = portnum
    self.results = []
    self.fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.starting = time.time()
    self.fd.setblocking(0)
    self.state = CONNECTING
    self.received_bytes = ''
    try:
      res = self.fd.connect_ex((self.host, self.port))
    except Exception, e:
      self.state = DEAD
      return
    if res == 0 or res == WSAEISCONN or res == WSAEWOULDBLOCK:
      if DEBUG and res == WSAEISCONN: 
        print "got that WSAEISCONN error after connect for " + hostname
      self.state = CONNECTED
    elif res != errno.EINPROGRESS:
      print "Connect error", res, errno.errorcode[res]
      self.state = DEAD
     
  
  def fileno(self):
    if self.state == DEAD:
      print "getting FD for dead guy", self
    return self.fd.fileno()

  def send_hello(self):
    "Try to send a Client Hello message; return True if things seem to be okay."
    try:
      sent = self.fd.send(hello_msg)
      self.state = DATA_SENT
    except Exception, e:
      self.record_error("Writing: " + `e`)
      self.state = DEAD
      return False

    if sent != len(hello_msg):
      self.record_error("Only sent %d of %d bytes" % (sent,len(msg)))
      self.state = DEAD
      return False

    return True

  def read_data(self):
    "Return True if we're now finished with this request."
    try:
      received = self.fd.recv(65535)
    except Exception, e:
      self.record_error("Reading:" + `e`)
      self.state = DEAD
      return True

    self.received_bytes += received
    if self.isDone():
      self.record_results()
      self.state = DONE
      return True
    else:
      if DEBUG: print "not done yet", self.host, len(self.received_bytes)
    if len(received) == 0:
      self.record_error("zero byte read recieved")
      self.state = DEAD
      if self.received_bytes:
        self.record_results(happy=False)
      return True
    return False

  
  def isDone(self):
    try:
      if (self.received_bytes):
        self.results = TLSRecord.parse(self.received_bytes)
    except Exception, e:
      if DEBUG: print "bad data - ", e, self.host, repr(self.received_bytes)
    for d in self.results:
      if DEBUG: print 'ct, len of data =', d.ContentType, len(d.data)
      if d.ContentType == 'handshake':
        try:
          handshake_messages = Handshake.parse(d.data)
          for x in handshake_messages:
            if DEBUG: print 'msg type, len =', x.msg_type, len(x.body)
            if x.msg_type == 'certificate':
              return True
        except Exception, e:
          print "X!", e, repr(d.data), repr(d.data[4:]),repr(d.data[6:]),repr(d.data[10:]),repr(d.data[38:])
    return False

  def record_error(self, reason):
    errorLog.write("failed reason: %s host: %s\n" % (reason, self.host))
    print "failed getting cert for:", self.host, reason
    self.fd.close()

  def record_results(self,happy=True):
    if happy:
      m = "happy: %s:%d %d\n" % (self.host, self.port, len(self.results))
      global complete_certs
      complete_certs +=1
    else:
      m = "partial: %s:%d %d\n" % (self.host, self.port, len(self.results))
      global partial_certs
      partial_certs +=1
    print m,
    errorLog.write(m)

    #try:
    path = results_path(self.host)
    f = open(path + ".results", 'wb')
    f.write(self.received_bytes)
    f.close()
    #except Exception, e:
    #  print "error", e, "recording results for", self.host

def results_path(host):
  # Return a path for writing results files to; if this is an IP address,
  # we use two layers of directories based on first and last quads
  try:
    socket.inet_aton(host)
  except:
    # This is a hostname
    return host

  # This is an IP address
  quads = host.split(".")
  # 127.x.x.x
  dir1 = quads[0] + ".x.x.x"
  # 127.x.x.x/127.x.x.1
  dir2 = dir1 + os.sep + quads[0] + ".x.x." + quads[3]
  for dir in [dir1,dir2]:
    if os.path.exists(dir):
      if not os.path.isdir(dir):
        raise IOError, dir1 + " exists but is not a directory" 
    else:
      os.mkdir(dir)
  return dir2 + os.sep + host

# -- done class CertificateRequest

class RequestMultiplexer:
  def __init__(self):
    self.pending = []
    self.moreAddresses = True

  def process_requests(self, reading, sending,  erroring):
    "Do work on the sockets that select() has told us are ready."
    if DEBUG:
      print "process_requests called rd: %d wr: %d err: %d pend: %d" %\
            (len(reading), len(sending), len(erroring), len(self.pending))
    
    for req in sending:
      assert (req.state == CONNECTED or req.state == CONNECTING)
      if not req.send_hello():
        self.pending.remove(req)
    
    for req in reading:
      if req.read_data():
        self.pending.remove(req)

    for req in erroring: 
      if req in self.pending:
        # Some kind of error that didn't get caught in the previous passes
        req.record_error("select said erroring")
        self.pending.remove(req)

  def monitor_timeouts(self):
    "Watch for requests that have been hanging around for too long"
    cur = time.time()
    for req in self.pending:
      if (req.state == CONNECTING and (cur - req.starting) > MAX_CONNECT_WAIT) or\
         ((cur - req.starting) > MAX_WAIT):
       req.record_error("timed out after %f seconds" % (cur - req.starting))
       req.state = DEAD
       self.pending.remove(req)
       if req.received_bytes:
         req.record_results(happy=False)

  def call_select(self):
    "Make and appropriate select() system call"
    reads = []
    writes = []
    for t in self.pending:
      # we want to write a hello message to these guys
      if t.state in [CONNECTING, CONNECTED]:
        writes.append(t)
      # and read a response from these
      elif t.state == DATA_SENT:
        reads.append(t)
    return select.select(reads, writes, self.pending, WAIT_TIME)

  def start_new_requests(self):
    # update pending with new addresses
    while (len(self.pending) < ALLOWED_ACTIVE and self.moreAddresses):
      try:
        address = self.addrs.pop()
      except IndexError:
        self.moreAddresses = False
        break
      if DEBUG: print "creating", address
      newGuy = CertificateRequest(address,  443)
      if newGuy.state != DEAD:
        self.pending.append(newGuy)

  def tend_to_requests(self):
    "Do any work we can on pending requests."
    try:
      rread, rwrite, inerror = self.call_select()
      self.process_requests(rread, rwrite, inerror)
      self.monitor_timeouts()
      if DEBUG: 
        print 'read', len(rread), 'write', len(rwrite), 'error', len(inerror),\
              len(self.pending), [p.host for p in self.pending]
    except:
      print "Unexpected error while tending to requests"
      raise

  def do_loop(self, addrs):
    self.addrs = addrs
    found = []
    running = True
    while (len(self.pending) > 0 or self.moreAddresses):
      self.start_new_requests()

      for x in self.pending:
        assert(x.state != DEAD)

      self.tend_to_requests()
    m = "Got %d complete and %d partial certs out of %d\n" % \
          (complete_certs, partial_certs, setsize)
    print m,
    errorLog.write(m)

# -- done class RequestMultiplexer

"prints the string value, show_per_line char at a time"
def pretty_print(value, show_per_line = 60):
  for pos in xrange(0, len(value), show_per_line):
    print '\t',pos,'\t', value[pos:pos + show_per_line]

def randomIPs(number):
  res = []
  for x in xrange(number):
    res.append(str(random.randint(0,255)) + '.' + \
      str(random.randint(0,255)) + '.' + \
      str(random.randint(0,255)) + '.' + \
      str(random.randint(0,255)))
  return res

input_file = ""

if __name__ == "__main__":
  if len(sys.argv) > 1:
    if sys.argv[1] == '-':
      testSites = sys.stdin.read().split()
    elif sys.argv[1] == '-f':
      input_file = sys.argv[2]
      testSites = open(input_file).read().split()
    else:
      testSites = sys.argv[1:]
  else:
    withCerts = ['www.isecpartners.com', 'www.eff.org', 'www.google.com', 
      'www.microsoft.com', 'mail.google.com', 'www.slashdot.org', 
      'yahoo.com', 'verisign.com',  'tmobile.com', 'sun.com', 
      'www.amazon.com', 'ibm.com', 'en.gandi.net' ]
    noCerts = ['localhost', 'secure.yahoo.com', 'www.groklaw.net', 
                'io9.com', 'insecure.org', 'verizon.com']
    testSites = withCerts + noCerts
    testSites.extend(randomIPs(2000))

  errorLog = open(time.strftime('Error_Log-'+input_file+'-%b-%d.txt'), 'w')
  global setsize
  setsize = len(testSites)
  m =  "Attempting to fetch %d certificates\n" % setsize
  print m,
  errorLog.write(m)

  random.shuffle(testSites)
  #if DEBUG: print Handshake.parse(TLSRecord.parse(binascii.a2b_hex(TLS_v1_CLIENT_HELLO))[0].data)
  RequestMultiplexer().do_loop(testSites)
# for host in testSites:
#   print 'trying:', host
#   result = getCert(host)
#   print 'len ==', len(result)
#   pretty_print(result)
#   print "----"

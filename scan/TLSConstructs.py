from construct import *

"Contructs for parsing TLS"

"A hacky class to represent a unsigned, 24 bit big-endian integer. Needed " +\
"for TLS's funny certificate lengths."
class UInt24(StaticField):
  def __init__(self, name):
    self.length = 3
    StaticField.__init__(self, name, self.length)
  def _parse(self, stream, context):
    try:
      d = core._read_stream(stream, self.length)
      return (ord(d[0]) * 65536) + (ord(d[1]) * 256) + ord(d[2])
    except Exception, ex:
      raise FieldError(ex)
  def _build(self, obj, stream, context):
    try:
      b= chr(obj / 65536) + chr((obj% 65536)/256) + chr((obj%256)) 
      core._write_stream(stream, self.length, b)
    except Exception, ex:
      raise FieldError(ex)

HandshakeType = Enum(UBInt8("msg_type"), hello_request=0, client_hello=1, 
                      server_hello=2, certificate=11, server_key_exchange=12,
                      certificate_request=13, server_hello_done=14, 
                      certificate_verify=15, client_key_exchange=16, 
                      finished=20)

CompressionMethod = Enum(Byte("compression_method"), null=0)

ProtocolVersion = Struct('ProtocolVersion', UBInt8('major'), UBInt8('minor'))

Random = Struct("random", UBInt32("gmt_unix_time"), String("random_bytes", 28))

HelloRequest = Struct("HelloRequest")

ClientHello = Struct("ClientHello", ProtocolVersion, Random, 
                      PascalString("session_id", 
                                  length_field=UBInt8("session_id_length")),
                      # hacky
                      PascalString("cipher_suites", 
                                  length_field=UBInt16("cipher_suites_length")),
                      PascalString("compression_methods", 
                                  length_field=UBInt8("compression_length")),
                      PascalString("extensions", 
                                  length_field=UBInt16("extensions_length"))
                      )
ServerHello = Struct("ServerHello", ProtocolVersion, Random, 
                      PascalString("session_id", 
                                  length_field=UBInt8("session_id_length")),
                      # hacky
                      PascalString("cipher_suites", 
                                  length_field=UBInt16("cipher_suites_length")),
                      PascalString("compression_methods", 
                                  length_field=UBInt8("compression_length")),
                      )

Certificate = Struct("Certificate", UInt24('list_length'), MetaField('list_data', lambda ctx: ctx.list_length))

ASNCert = Struct("ASNCert", UInt24('cert_length'), MetaField('cert', lambda ctx: ctx.cert_length))

Handshake = GreedyRepeater(Struct("Handshake", 
                    HandshakeType, 
                    UInt24("length"), # 24-bit length akward, 
                   # Probe("handshake message decode before body"),
                    MetaField('body', lambda ctx: ctx.length)
#                    Switch("body", lambda ctx: ctx["msg_type"],
#                      {
#                        "hello_request" : Embed(HelloRequest),
#                        "client_hello" : Embed(ClientHello),
#                        "server_hello" : Embed(ServerHello)#,
#                       "certificate" : Embed(Certificate),
#                       "server_key_exchange" : Embed(ServerKeyExchange),
#                       "certificate_request" : Embed(CertificatRequest),
#                       "server_hello_done" : Embed(ServerHelloDone),
#                       "certificate_verify" : Embed(CertificateVerify),
#                       "client_key_exchange" : Embed(ClientKeyExchange),
#                       "finished" : Embed(Finished)                        
#                      }
#                    )
              ))

ContentType = Enum(UBInt8('ContentType'), 
                  change_cipher_spec = 20, 
                  alert=21, 
                  handshake=22, 
                  application_data=23)


TLSRecord = GreedyRepeater(Struct("TLSRecord", 
                ContentType,
                ProtocolVersion,
                UBInt16("length"),
                MetaField('data', lambda ctx: ctx.length) 
                ) )

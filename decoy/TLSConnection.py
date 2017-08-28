__author__ = 'milad'

from scapy_ssl_tls.ssl_tls import TLS
import scapy_ssl_tls.ssl_tls
from scapy.all import Ether,IP,TCP
import datetime
import re
from cryptography.hazmat.backends import default_backend
#from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends.openssl import backend
import pickle
import base64
from cryptography.hazmat.primitives import serialization
from scapy.all import rdpcap
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pyasn1.type import univ
import struct
from pyasn1.codec.ber import encoder, decoder
from cryptography.hazmat.primitives.ciphers import AEADCipherContext, Cipher, algorithms, modes
from Crypto.Cipher import AES
import threading
import XRelay
import tinyec.ec as ec
import tinyec.registry as ec_reg
import binascii
from scapy_ssl_tls.ssl_tls_crypto import TLSPRF
import uuid


def int_to_str(int_):
    hex_ = "%x" % int_
    return binascii.unhexlify("%s%s" % ("" if len(hex_) % 2 == 0 else "0", hex_))

def str_to_ec_point(ansi_str, ec_curve):
    if not ansi_str.startswith("\x04"):
        raise ValueError("ANSI octet string missing point prefix (0x04)")
    ansi_str = ansi_str[1:]
    if len(ansi_str) % 2 != 0:
        raise ValueError("Can't parse curve point. Odd ANSI string length")
    str_to_int = lambda x: int(binascii.hexlify(x), 16)
    x, y = str_to_int(ansi_str[:len(ansi_str) // 2]), str_to_int(ansi_str[len(ansi_str) // 2:])
    return ec.Point(ec_curve, x, y)


class TLSConnection:
    def __init__(self):
        self.carry = ''
        self.serverrandom = ''
        self.clientrandom = ''

        for i in range(32):
            if i< 4:
                self.clientrandom+=chr(0)
            else:
                self.clientrandom+=chr(i)

        self.serverpub = ''
        self.replacepayloads = []
        self.masterkey = ''
        self.serverpubkey = ''
        self.candecrypt = False
        self.replacedpackets = {}
        self.testlock = threading.Lock()
        self.mac_key_length = 32
        self.cipher_key_length = 16
        self.iv_length = 16
        self.encryptor = None
        self.datacarry = ''
        self.writemode = None
        self.writesecret = 'MILAD SECRET'
        self.writekey = ''

        self.prf = TLSPRF(0x0303)
        self.manager = XRelay.Relay()
        self.headersize = 5
        self.connid = uuid.uuid4().bytes
        self.startreplace = False



    def driveKeys(self):

        #pk= ec.generate_private_key(ec.SECP256R1, backend)


        ec_curve = ec_reg.get_curve('secp256r1')
        server_keypair = ec.Keypair(ec_curve, pub= str_to_ec_point(self.serverpub,ec_curve))

        client_keypair=pickle.load(open('clientpriv'))
        secret_point = ec.ECDH(client_keypair).get_secret(server_keypair)
        mk = int_to_str(secret_point.x)


        pshare=self.prf.get_bytes(mk,'master secret',self.clientrandom+self.serverrandom,num_bytes=48)





        target_len=128
        blockkey=self.prf.get_bytes(pshare,'key expansion',self.serverrandom+self.clientrandom,num_bytes=target_len)
        print [ord(i) for i in blockkey]
        i = 0
        self.client_write_MAC_key = blockkey[i:i+self.mac_key_length]
        i += self.mac_key_length
        self.server_write_MAC_key = blockkey[i:i+self.mac_key_length]
        i += self.mac_key_length
        self.client_write_key = blockkey[i:i+self.cipher_key_length]
        i += self.cipher_key_length
        self.server_write_key = blockkey[i:i+self.cipher_key_length]
        i += self.cipher_key_length


        self.client_write_IV = blockkey[i:i+self.iv_length]
        i += self.iv_length
        self.server_write_IV = blockkey[i:i+self.iv_length]
        i += self.iv_length

        self.httpcarry=''



        self.initDecryptor()
        #print [ord(i) for i in self.clientrandom]
        #print [ord(i) for i in self.serverrandom]
        #print [ord(i) for i in self.ivkey]

        print 'Keys are in place'

    def initDecryptor(self):
        # self.mode= modes.CBC(self.server_write_IV)
        # self.mode= modes.GCM(self.server_write_IV)
        # self.cipher = Cipher(algorithms.AES(self.server_write_key) ,self.mode , backend=backend)   #AES.new(self.server_write_key,AES.MODE_CBC,self.server_write_IV) #
        # self.decryptor= self.cipher.decryptor()
        self.candecrypt=True
        pass

    def get_nonce(self, nonce=None):
        import struct
        nonce = nonce or struct.pack("!Q", self.ctx.nonce)
        return b"%s%s" % (self.server_write_iv, nonce)

    def decrypt(self,cipherdata):
        ####
        nonce, cdata, tag = cipherdata[:8], cipherdata[8:-16], cipherdata[-16:]
        assert len(tag) == 16
        assert len(cdata) == len(cipherdata) - 16 -8
        # self.mode = modes.GCM(self.server_write_IV, tag=tag)
        # print("DECRYPTING")
        # print("NONCE", nonce)
        # print("DATA", cdata)
        # print("TAG", tag)
        # # print("WRITE_IV", self.server_write_IV)
        # print("WRITE KEY", self.server_write_key)
        nonce = self.get_nonce(nonce)
        try:
            self.mode = modes.GCM(nonce, tag=tag)
            self.cipher = Cipher(algorithms.AES(self.server_write_key) ,self.mode , backend=backend)   #AES.new(self.server_write_key,AES.MODE_CBC,self.server_write_IV) #
            
            self.decryptor= self.cipher.decryptor()
            self.candecrypt=True
            ###
            assert self.candecrypt
            plaindata=self.decryptor.update(cdata)# + self.decryptor.finalize()
            padding= ord(plaindata[-1])
            d = plaindata[16:-(1+padding+self.mac_key_length)]
            return d
        except:
            raise

        # ATTEMP 2

        # crypto_data = CryptoData.from_context(self.tls_ctx, self.ctx, "\x00" * len(ciphertext))
        # crypto_data.content_type = content_type
        # crypto_container = EAEADCryptoContainer.from_context(self.tls_ctx, self.ctx, crypto_data)
        # self.__init_ciphers(self.get_nonce(explicit_nonce))
        # self.dec_cipher.update(crypto_container.aead)
        # cleartext = self.dec_cipher.decrypt(ciphertext)
        # try:
        #     self.dec_cipher.verify(tag)
        # except ValueError as why:
        #     warnings.warn("Verification of GCM tag failed: %s" % why)
        # self.ctx.nonce = struct.unpack("!Q", explicit_nonce)[0]
        # self.ctx.sequence += 1
        # return "%s%s%s" % (explicit_nonce, cleartext, tag)
            # return ''


    def addDATA(self,data):
        self.datacarry+=data
        flag=True

        while flag:

            cmd= struct.unpack('>c',self.datacarry[:1])[0]
            print 'GET COMMAND',cmd
            size=struct.unpack('>I',self.datacarry[1:5])[0]
            if size+self.headersize<=len(self.datacarry):

                if cmd=='S':

                    newdata= self.datacarry[:size+self.headersize]
                    self.startreplace=True
                    #print newdata[5:],size,cmd
                    assert 16==size
                    pl=newdata[self.headersize:self.headersize+size]
                    resp='%s%s%s%s'%('0'*16,struct.pack('>c','R'),struct.pack('>I',len(pl)),pl)
                    self.replacepayloads.append(resp)

                else:
                    self.manager.processCMD(self.datacarry[:size+5],self.connid)
                if size+5 == len(self.datacarry):
                    self.datacarry=''
                    flag=False
                else:
                    self.datacarry=self.datacarry[size+5:]
            else:
                flag=False

    def addHTTPpacket(self,pkt):
        if  not '/~milad' in pkt:
            return
        reg=re.search(r'/~milad/(\S+)',pkt)
        #print 'raw', pkt
        if reg:

            dec=base64.b64decode( reg.group(1))
            self.addDATA(dec)


    def retrivepackets(self):
        self.replacepayloads.extend( self.manager.getnewpackets(self.connid))




    def getnewpayload(self,size,seq):
        self.retrivepackets()
        if seq in self.replacedpackets:
            return self.replacedpackets[seq]


        if len(self.replacepayloads)==0:
            return ''


        ret=''

        while size>0 and len(self.replacepayloads)>0:
            data=self.replacepayloads.pop(0)
            if len(data)> size:
                ret+=data[:size]

                #print 'DATA LARGER'
                self.replacepayloads.insert(0,data[size:])
                size=0

            else:
                ret+=data
                size-=len(data)
        print 'getting new packet',datetime.datetime.now()

        self.replacedpackets[seq]=ret
        return ret






    def processTLSpacket(self,pkt):
        mtls=TLS(pkt)

        if scapy_ssl_tls.ssl_tls.TLSServerHello in mtls:
            self.serverrandom= str(mtls[scapy_ssl_tls.ssl_tls.TLSServerHello])[2:34]
            print 'Server Random Found'
        if scapy_ssl_tls.ssl_tls.TLSClientHello in mtls:
            self.clientrandom= str(mtls[scapy_ssl_tls.ssl_tls.TLSClientHello])[2:34]
            #mtls[scapy_ssl_tls.ssl_tls.TLSClientHello].show2()
            #print [ord(i) for i in str(mtls[scapy_ssl_tls.ssl_tls.TLSClientHello])[:40]]
            print [ord(i) for i in self.clientrandom]
            print 'Client Random Found'
        if scapy_ssl_tls.ssl_tls.TLSServerKeyExchange in mtls:
            server_kex = mtls[scapy_ssl_tls.ssl_tls.TLSServerKeyExchange]
            a = server_kex[scapy_ssl_tls.ssl_tls.TLSServerECDHParams]
            point = scapy_ssl_tls.ssl_tls_keystore.ansi_str_to_point(a.p)
            self.serverpub=a.p
            curve = ec_reg.get_curve('secp256r1')
            scapy_ssl_tls.ssl_tls_keystore.ECDHKeyStore(curve, ec.Point(curve, *point))


            # PREMASTER KEY
            ec_curve = ec_reg.get_curve('secp256r1')
            server_keypair = ec.Keypair(ec_curve, pub= str_to_ec_point(self.serverpub,ec_curve))
            client_keypair=pickle.load(open('clientpriv'))
            secret_point = ec.ECDH(client_keypair).get_secret(server_keypair)
            mk = int_to_str(secret_point.x) # masalan premaster key

            sec_params = scapy_ssl_tls.ssl_tls_crypto.TLSSecurityParameters.from_pre_master_secret(self.prf, scapy_ssl_tls.ssl_tls.TLSCipherSuite.ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                                                                       mk, self.clientrandom,
                                                                       self.serverrandom)
            sym_keystore = sec_params.server_keystore        
            # print("SYYYYYN JEEEEEET", sym_keystore.key)                                                               
            self.server_write_key = sym_keystore.key
            self.server_write_iv = sym_keystore.iv
            self.candecrypt = True
            # ecdh=scapy_ssl_tls.ssl_tls.TLSServerECDHParams(str(mtls[scapy_ssl_tls.ssl_tls.TLSServerKeyExchange]))
            # self.serverpub=ecdh.p
            # print 'server public Found'
            # self.driveKeys()

        if self.candecrypt:
            # print 'decrypting '
            # mtls.show2()
            if scapy_ssl_tls.ssl_tls.TLSCiphertext in mtls:
                # print 'decryptable'
                plain=self.decrypt(mtls[scapy_ssl_tls.ssl_tls.TLSCiphertext].data)

                if mtls.records[0].content_type==23:
                    self.startreplace=True
                    #print plain[:60]
                    self.addHTTPpacket(plain)



    def addTLSPacket(self,pkt):

        flag=True

        self.carry+=str(pkt)




        #TLS(carry).show2()

        while flag:

            try:
                plen= TLS(self.carry).records[0].length#[scapy_ssl_tls.ssl_tls.TLSRecord].length
                #TLS(self.carry).show2()
            except:
                #TLS(self.carry).show2()
                #print len(self.carry),len(pkt)
                break


            #print plen
            if plen+5<= len(self.carry):
                self.processTLSpacket(self.carry[:plen+5])
                try:
                    if plen+5 ==len(self.carry):
                        self.carry=''
                        flag=False
                    else:
                        self.carry=self.carry[plen+5:]
                except:
                    print 'error' , len (self.carry), plen+5
            else:
                flag=False



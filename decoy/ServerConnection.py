from __future__ import print_function
#print = lambda x: sys.stdout.write("%s\n" % x)
__author__ = 'milad'

import select
import socket
import sys
import os
import fcntl
import logging
import traceback
import struct
import uuid
import datetime

class ProxyConnection(object):

    # enable a buffer on connections with this many bytes
    MAX_BUFFER_SIZE = 1024

    # ProxyConnection class forwards data between a client and a destination socket

    def __init__(self,serv_addr,clientid):
        self.conid=uuid.uuid4().bytes
        self.clientid=clientid
        self.sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)


        self.sock.connect(serv_addr)


class ProxyServer(object):

    def __init__(self,addr):
        self.address = addr

        self.listensock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listensock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listensock.bind(self.address)
        self.listensock.listen(5)
        self.connections = {}
        self.revcon = {}# map from a socket to a ProxyConnection
        self.readsockets = []               # all sockets which can be read
        self.writesockets = []              # all sockets which can be written
        self.allsockets = [self.listensock] # all opened sockets
        self.connection_count = 0           # count of all active connections
        self.clientsocket = None
        self.datacarry = ''
        self.clientsocks = []

    def run(self):
        loop = 0
        while True:
            # block until there is some activity on one of the sockets, timeout every 60 seconds by default
            r, w, e = select.select(
                            [self.listensock]+self.readsockets+self.clientsocks,
                            [],
                            [self.listensock]+self.readsockets)
            loop += 1
            # handle any reads
            for s in r:
                if s is self.listensock:
                    # open a new connection
                    clientsocket,clientaddr=s.accept()
                    self.clientsocks.append(clientsocket)

                elif s in self.clientsocks:
                    newcon=s.recv(4096)

                    self.addDATA(newcon)

                else:
                    if s in self.connections:

                        try:
                            data=s.recv(4096)

                        except:
                            data=''
                        pr=self.connections[s]
                        if len(data)==0:
                            self.communicate(pr.clientid,pr.conid,'F',data)
                            self.deactivateRead(self.revcon[pr.conid])
                            del self.revcon[pr.conid]

                            s.close()
                        else:

                            self.communicate(pr.clientid,pr.conid,'D',data)



        self.sock.close()
        self.sock = None

    def addDATA(self,data):
        self.datacarry+=data
        flag=True

        while flag:
            if len(self.datacarry)<21:
                break
            connid=self.datacarry[:16]
            cmd= struct.unpack('>c',self.datacarry[16:17])[0]
            size=struct.unpack('>I',self.datacarry[17:21])[0]
            if size+21<=len(self.datacarry):
                newpkt=self.datacarry[21:size+21]
                #print ("DATA ",cmd," size",size)
                try:
                    if cmd=='O':
                        try:
                            sockid=newpkt[:16]
                            self.revcon[sockid].sendall(newpkt[16:])
                        except:
                            self.communicate(connid,sockid,'F','')
                    elif cmd=='N':
                        newcon=newpkt
                        #print (newcon)
                        try:
                            clid,ip,port= newcon[:16],newcon[16:].split(':')[0],int(newcon[16:].split(':')[1])
                            self.open((ip,port),connid,clid)

                        except:
                            print ('ERROR',newcon)
                            traceback.print_exc(file=sys.stderr)
                    elif cmd=='Q':


                        sockid=newpkt[:16]
                        self.deactivateRead(self.revcon[sockid])

                        self.revcon[sockid].close()

                        del self.revcon[sockid]
                except:
                    traceback.print_exc(file=sys.stderr)
                if size+21 == len(self.datacarry):
                    self.datacarry=''
                    flag=False
                else:
                    self.datacarry=self.datacarry[size+21:]

            else:
                flag=False

    def activateRead(self,sock):
        if not sock in self.readsockets:
            self.readsockets.append(sock)

    def deactivateRead(self,sock):
        if sock in self.readsockets:
            self.readsockets.remove(sock)

    def activateWrite(self,sock):
        if not sock in self.writesockets:
            self.writesockets.append(sock)

    def deactivateWrite(self,sock):
        if sock in self.writesockets:
            self.writesockets.remove(sock)

    def registerSocket(self,sock,conn):
        self.connections[sock] = conn
        self.allsockets.append(sock)

    def unregisterSocket(self,sock,conn):
        del self.connections[sock]
        self.allsockets.remove(sock)

    # open a new proxy connection from the listening socket
    def communicate(self,clientid,conid,CMD,data):
        print ('sendding command',CMD,datetime.datetime.now())
        for c in self.clientsocks:
            c.sendall('%s%s%s%s%s'%(clientid,conid,struct.pack('>c',CMD),struct.pack('>I',len(data)),data))


    def open(self,server,clientid,clid):

        print ('NEW CONNECTION %s'%server[0])
        conn = ProxyConnection(server,clientid)
        self.connections[conn.sock]=conn
        self.revcon[conn.conid]=conn.sock
        self.activateRead(conn.sock)
        self.communicate(conn.clientid,conn.conid,'C',clid)



if __name__ == '__main__':
    try:
        proxy = sys.argv[1].split(":")
        dest = sys.argv[2].split(":")
        proxyhost = proxy[0]
        proxyport = int(proxy[1])
        serverhost = dest[0]
        serverport = int(dest[1])
    except:
        sys.exit(-1)

    logger = logging.getLogger('simpleproxy')
    logger.setLevel(logging.INFO)
    hdlr = logging.StreamHandler()
    hdlr.setLevel(logging.INFO)
    hdlr.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(hdlr)



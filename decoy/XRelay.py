__author__ = 'milad'

import datetime
import socket
import select
import time
import sys
import traceback
import httplib
import ssl
import threading
import base64
import SocketServer
import fcntl
serv_addr=('localhost',8979)

import os
from ServerConnection import ProxyServer
import struct
import errno


class RelayManager():
    def __init__(self):

        self.server = ProxyServer(serv_addr)
        self.serverconnectionthread = threading.Thread(target=self.server.run).start()

        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.conn.connect(serv_addr)
        #fcntl.fcntl(self.conn, fcntl.F_SETFL, os.O_NONBLOCK)
        self.datacarry=''
        self.headersize=37
        self.connections={}
        self.sendlock=threading.Lock()
        self.recvlock=threading.Lock()


    def processCMD(self,pkt,connid):
        with self.sendlock:
            self.conn.sendall(str(connid)+pkt)


    def processDATA(self,data):
        self.datacarry+=data

        flag=True
        while flag:
            if len(self.datacarry)<self.headersize:
                break
            connid=self.datacarry[:16]
            size=struct.unpack('>I', self.datacarry[33:37])[0]
            if size+ self.headersize <= len(self.datacarry):
                self.connections.setdefault(connid,[]).append(self.datacarry[16:size+ self.headersize ])
                if size+ self.headersize == len(self.datacarry):
                    self.datacarry=''
                    flag=False
                else:
                    self.datacarry=self.datacarry[size+ self.headersize:]

            else:
                flag=False


    def autofetch(self):
        while True:
            r,w,e=select.select([self.conn],[],[])
            if r :
                msg = self.conn.recv(4096)
                print 'get data from serverconnection',datetime.datetime.now()
                self.processDATA(msg)


    def getnewpackets(self,connid):
        return self.connections.pop(connid,[])




class Relay():
    _manager=None

    def __init__(self):
        if Relay._manager==None:
            Relay._manager= RelayManager()
            threading.Thread(target=Relay._manager.autofetch).start()

    def __getattr__(self, item):
        return getattr(self._manager, item)

    def __setattr__(self, key, value):
        return setattr(self._manager, key, value)
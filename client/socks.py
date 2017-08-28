import struct

from twisted.internet import protocol


class Socks5Protocol(protocol.Protocol):
    def __init__(self):
        self.state = ''
        self.remote = None

    def connectionMade(self):
        self.state = 'wait_hello'

    def dataReceived(self, data):
        method = getattr(self, self.state)
        method(data)

    def wait_hello(self, data):
        (ver, nmethods) = struct.unpack('!BB', data[:2])
        if ver != 5:
            # we do SOCKS5 only
            self.transport.loseConnection()
            return
        if nmethods < 1:
            # not SOCKS5 protocol?!
            self.transport.loseConnection()
            return
        methods = data[2:2 + nmethods]
        for meth in methods:
            if ord(meth) == 0:
                # no auth, neato, accept
                resp = struct.pack('!BB', 5, 0)
                self.transport.write(resp)
                self.state = 'wait_connect'
                return
            if ord(meth) == 255:
                # disconnect
                self.transport.loseConnection()
                return
        # -- we should have processed the request by now
        self.transport.loseConnection()

    def wait_connect(self, data):
        (ver, cmd, rsv, atyp) = struct.unpack('!BBBB', data[:4])
        if ver != 5 or rsv != 0:
            # protocol violation
            self.transport.loseConnection()
            return
        data = data[4:]
        if cmd == 1:
            host = None
            if atyp == 1:  # IP V4
                (b1, b2, b3, b4) = struct.unpack('!BBBB', data[:4])
                host = '%i.%i.%i.%i' % (b1, b2, b3, b4)
                data = data[4:]
            elif atyp == 3:  # domainname
                l, = struct.unpack('!B', data[:1])
                host = data[1:1 + l]
                data = data[1 + l:]
            elif atyp == 4:  # IP V6
                raise RuntimeError("IPV6 not supported")
            else:
                # protocol violation
                self.transport.loseConnection()
                return
            (port) = struct.unpack('!H', data[:2])
            port = port[0]
            data = data[2:]
            return self.perform_connect(host, port)
        elif cmd == 2:
            raise NotImplementedError("SOCKS Bind not implemented")
        elif cmd == 3:
            raise NotImplementedError("SOCKS UDP not implemented")

        # -- we should have processed the request by now
        self.transport.loseConnection()

    def send_connect_response(self, code):
        try:
            myname = self.transport.getHost().host
        except:
            # this might fail as no longer a socket
            # is present
            self.transport.loseConnection()
            return
        ip = [int(i) for i in myname.split('.')]
        resp = struct.pack('!BBBB', 5, code, 0, 1)
        resp += struct.pack('!BBBB', ip[0], ip[1], ip[2], ip[3])
        resp += struct.pack('!H', self.transport.getHost().port)
        self.transport.write(resp)

    def perform_connect(self, host, port):
        if hasattr(self.factory, 'on_socks_connect'):
            self.factory.on_socks_connect(self, host, port)
        # if self.on_connect is not None:
        #     self.on_connect(self, host, port)

    def start_remote_communication(self, remote):
        self.remote = remote
        self.send_connect_response(0)
        self.state = 'communicate'

    def communicate(self, data):
        self.remote.send(data)

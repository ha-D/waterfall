__author__ = 'milad'
from scapy.all import Ether,IP,TCP


class TCPConnection():
    def __init__(self, seq):
        self.packets = {}
        self.nextseq = seq

    def addpacket(self, pkt):
        ret = False
        if pkt[TCP].seq in self.packets and len(str(pkt[TCP].payload)) > 0:
            ret = True
        self.packets[pkt[TCP].seq] = pkt
        return ret

    def getpacket(self):
        ret = []
        while True:
            if self.nextseq in self.packets:
                #print 'before',self.nextseq
                pkt = self.packets.get(self.nextseq)
                self.nextseq += len((pkt[TCP].payload))
                #print 'after',self.nextseq
                ret.append(  pkt)
            else:
                break
        return ret


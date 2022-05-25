# from scapy.all import ARP, Ether, srp
from scapy.all import *

def delfl(s):
    s = s.split('  ')
    s.pop()
    s.pop(0)
    return s

def clearHexDump(s: str):
    return '\n'.join(map(lambda a : ' '.join(delfl(a)), list(s.splitlines())))

def scann():
    capture = sniff(iface = conf.iface, count = 1, filter='ip and tcp and tcp[12:1] >= 0x50 and tcp[12:1] <= 0x5F', prn=lambda x:x.summary())
    pk = capture.pop()
    pk.pdfdump(layer_shift=1)
    pk.psdump("/tmp/isakmp_pkt.eps",layer_shift=1)
    return clearHexDump(hexdump(pk, True))
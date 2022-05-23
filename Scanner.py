# from scapy.all import ARP, Ether, srp
from scapy.all import *

# ip = get_if_addr(conf.iface)  # default interface
# ip = list(ip.split('.'))
# ip.pop()
# target_ip = "192.168.1.1/22"
# target_ip = '.'.join(ip) + ".1/24"

# request = ARP()
  
# request.pdst = target_ip
# broadcast = Ether()
  
# broadcast.dst = 'ff:ff:ff:ff:ff:ff'
  
# request_broadcast = broadcast / request
# clients = srp(request_broadcast, timeout = 1)[0]
# for element in clients:
#     print(element[1].psrc + "      " + element[1].hwsrc) 
def delfl(s):
    s = s.split('  ')
    s.pop()
    s.pop(0)
    return s

def clearHexDump(s: str):
    print(s)
    return '\n'.join(map(lambda a : ' '.join(delfl(a)), list(s.splitlines())))

def scann():
    capture = sniff(iface = conf.iface, count = 1, filter='ip and tcp', prn=lambda x:x.summary())
    for a in capture:
        return clearHexDump(hexdump(a, True))
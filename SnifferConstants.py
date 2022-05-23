# General constants
NO_CHAR = ''
SPACE = ' '
DOT = '.'
ENDL = '\n'
BYTE_HEX_LEN = 2
BIT_LEN = 1
BYTE_SEPARATOR_LEN = 1
HEX_SCALE = 16
BIN_SCALE = 2
BITS_PER_HEX = 8

TURN_TO_BITS = 'turn_to_bits'
TURN_TO_BYTES = 'turn_to_bytes'

# Root window constants
ROOTWINDOWSIZE = "400x300"
LABEL_FONT = ('Modern',16)
TEXT_FONT = ('Calibri', 15)
TITLE_FONT = ('Script', 20)
ROW_HEIGHT = 2

IP_PROTOCOL = dict({
    '00': 'Reservado',
    '01': 'ICMP (“Internet Control MessageProtocol”)',
    '02': 'IGMP (“Internet Group ManagementProtocol”)',
    '03': 'GGP (“Gateway-to-Gateway Protocol”)',
    '04': 'IP (IP encapsulation)',
    '05': 'Flujo (“Stream”)',
    '06': 'TCP (“Transmission Control”)',
    '07': 'EGP (“Exterior Gateway Protocol”)',
    '08': 'PIRP (“Private Interior RoutingProtocol”)',
    '17': 'UDP (“User Datagram”)',
    '89': 'OSPF (“Open Shortest Path First”)'
})
TOS_PRECEDENCE = dict({
    '000': 'Rutina',
    '001': 'Prioridad',
    '010': 'Inmediato',
    '011': 'Flash',
    '100': 'Flash override',
    '101': 'Critico',
    '110': 'Internetwork control',
    '111': 'Network control'
})
TOS_TYPE = dict({
    '1000': 'Minimizar retardo',
    '0100': 'Maximizar la densidad del flujo',
    '0010': 'Maximizar la fiabilidad',
    '0001': 'Minimizar el costo monetario',
    '0000': 'Servicio normal'
})
SERVICES = dict({
    "0800": "Internet Protocol version 4 (IPv4)", 
    "0806":"Address Resolution Protocol (ARP)",
    "0842":"Wake-on-LAN",
    "22F3":"IETF TRILL Protocol",
    "6003":"DECnet Phase IV",
    "8035":"Reverse Address Resolution Protocol",
    "809B":"AppleTalk (Ethertalk)",
    "80F3":"AppleTalk Address Resolution Protocol (AARP)",
    "8100":"VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq",
    "8137":"IPX",
    "8204":"QNX Qnet",
    "86DD":"Internet Protocol Version 6(IPv6)",
    "8808": "Ethernet flow control",
    "8819":"CobraNet",
    "8847":"MPLS unicast",
    "8848":"MPLS multicast",
    "8863":"PPPoE Discovery Stage",
    "8864":"PPPoE Session Stage",
    "8870":"Jumbo Frames (proposed)",
    "887B":"HomePlug 1.0 MME",
    "888E":"EAP over LAN (IEEE 802.1X)",
    "8892":"PROFINET Protocol",
    "889A":"HyperSCSI (SCSI over Ethernet)",
    "88A2":"ATA over Ethernet",
    "88A4":"EtherCAT Protocol",
    "88A8":"Provider Bridging (IEEE 802.1ad) & Shortest Path Bridging IEEE 802.1aq",
    "88AB":"Ethernet Powerlink",
    "88CC":"Link Layer Discovery Protocol (LLDP)",
    "88CD":"SERCOS III",
    "88E1":"HomePlug AV MME",
    "88E3":"Media Redundancy Protocol (IEC62439-2)",
    "88E5":"MAC security (IEEE 802.1AE)",
    "88E7":"Provider Backbone Bridges (PBB) (IEEE 802.1ah)",
    "88F7":"Precision Time Protocol (PTP) over Ethernet (IEEE 1588)",
    "8902":"IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)",
    "8906":"Fibre Channel over Ethernet (FCoE)",
    "8914":"FCoE Initialization Protocol",
    "8915":"RDMA over Converged Ethernet (RoCE)",
    "891D":"TTEthernet Protocol Control Frame (TTE)",
    "892F":"High-availability Seamless Redundancy (HSR)",
    "9000":"Ethernet Configuration Testing Protocol",
})
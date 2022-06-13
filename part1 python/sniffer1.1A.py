from scapy.all import *
print("sniffing packets")

def print_pkt(pkt):
    pkt.show()


packet = sniff(iface = "br-ae32e9ad3ed5",filter ="icmp", prn= print_pkt)


from scapy.all import *
print("sniffing packets")

def print_pkt(pkt):
    pkt.show()

#(filter = "icmp", prn= print_pkt)# part 1
packet = sniff(iface = "br-ae32e9ad3ed5", filter = "tcp", prn= print_pkt) #part 2
#packet = sniff(filter = "icmp and host 8.8.8.8", prn= print_pkt) #part 3 

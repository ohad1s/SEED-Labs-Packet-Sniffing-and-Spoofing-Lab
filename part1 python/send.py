from scapy.all import *
print("send packets")
send(IP(dst='10.9.0.6')/TCP(dport=23, flags='S'))

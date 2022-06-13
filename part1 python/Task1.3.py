from scapy.all import *

a = IP(dst = '172.217.171.206', ttl = 9) # you can chnge the ttl until you got replay
b = ICMP()
p = a/b
ls(a)
send(p)

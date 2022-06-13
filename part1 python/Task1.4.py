from scapy.all import *

def spoof(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:
        print("start sniff")
        print("original source:", pkt[IP].src)
        print("original dest:", pkt[IP].dst)

        ip = IP(src= pkt[IP].dst, dst = pkt[IP].src, ihl =pkt[IP].ihl)
        icmp = ICMP(type=0,id=pkt[ICMP].id,seq = pkt[ICMP].seq)
        data = pkt[Raw].load
        newpkt = ip/icmp/data
        
        print("spoof")
        print("spoof source:", newpkt[IP].src)
        print("spoof dest:", newpkt[IP].dst)
        send(newpkt,verbose=0)
packet = sniff(iface = 'br-ae32e9ad3ed5',filter='icmp',prn=spoof)
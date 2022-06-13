#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
/* This function will be invoked by pcap for each captured packet.
We can process each packet inside the function.
*/
void got_packet(u_char *args, const struct pcap_pkthdr *header,
const u_char *packet)
{
printf("Got a packet\n");

	struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
    //struct iphdr *iph = (struct iphdr *)(packet+ETH_HLEN);
        unsigned short ip_hdr_len;
            ip_hdr_len = iph->ihl * 4;
                        struct sockaddr_in src;
           memset(&src, 0, sizeof(src));
            src.sin_addr.s_addr = iph->saddr;

           struct sockaddr_in dest;
            memset(&dest, 0, sizeof(dest));
            dest.sin_addr.s_addr = iph->daddr;
                       printf("Source IP is: %s\n", inet_ntoa(src.sin_addr));
           printf("Destination IP is: %s\n", inet_ntoa(dest.sin_addr));
}
int main()
{
pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
char filter_exp[] = "icmp";
bpf_u_int32 net;
// Step 1: Open live pcap session on NIC with name eth3.
// Students need to change "eth3" to the name found on their own
// machines (using ifconfig). The interface to the 10.9.0.0/24
// network has a prefix "br-" (if the container setup is used).
handle = pcap_open_live("br-f1814131d25c", BUFSIZ, 1, 1000, errbuf);
// Step 2: Compile filter_exp into BPF psuedo-code
pcap_compile(handle, &fp, filter_exp, 0, net);
if (pcap_setfilter(handle, &fp) !=0) {
    pcap_perror(handle, "Error:");
exit(EXIT_FAILURE);
}
// Step 3: Capture packets
pcap_loop(handle, -1, got_packet, NULL);
pcap_close(handle); //Close the handle
return 0;
}
// Note: don’t forget to add "-lpcap" to the compilation command.
// For example: gcc -o sniff sniff.c -lpcap
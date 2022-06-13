#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

//  #include <libnet.h>
#include<netinet/tcp.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};


/* This function will be invoked by pcap for each captured packet.
We can process each packet inside the function.
*/
void got_packet(u_char *args, const struct pcap_pkthdr *header,
const u_char *packet)
{
printf("Got a packet\n");
	struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
        unsigned short ip_hdr_len;
    if (iph->protocol== IPPROTO_TCP) {
        ip_hdr_len = iph->ihl * 4;
        struct tcpheader *tcph = (struct tcpheader *) (packet + ip_hdr_len +ETH_HLEN);

            struct sockaddr_in src;
            memset(&src, 0, sizeof(src));
            src.sin_addr.s_addr = iph->saddr;

            struct sockaddr_in dest;
            memset(&dest, 0, sizeof(dest));
            dest.sin_addr.s_addr = iph->daddr;


            printf("\n");

            printf("\n****************** TCP Packet ******************\n");
            printf("Source IP is: %s\n", inet_ntoa(src.sin_addr));
            printf("Destination IP is: %s\n", inet_ntoa(dest.sin_addr));
            printf("Source Port is: %d\n", ntohs(tcph->tcp_sport));
            printf("Destanation Port is: %d\n", ntohs(tcph->tcp_dport));
            printf("Data: %s\n",packet+ ip_hdr_len+ETH_HLEN+sizeof(struct tcpheader));
        
    }

}
int main()
{
pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
char filter_exp[] = "proto TCP and dst portrange 10-100";
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
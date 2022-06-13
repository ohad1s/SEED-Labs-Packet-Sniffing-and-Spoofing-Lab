// 2.3
// sniff and then spoof

#include <stdio.h>

#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pcap.h>



// IPv4 header len without options
#define IP4_HDRLEN 20

// ICMP header len for echo reply (with time stamp)
#define ICMP_HDRLEN 16

//ETHER header len
#define SIZE_ETHERNET 14

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

// Checksum algo
// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short *paddress, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *((unsigned char *) &answer) = *((unsigned char *) w);
        sum += answer;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}

int main() {

    pcap_t *handle; //pcap handle pointer for sniffing
    char errbuf[PCAP_ERRBUF_SIZE]; //for error prompt
    struct bpf_program fp; // the filtering program: bpf
    // set the filter -> icmp.
    char filter_exp[] = "icmp";
    bpf_u_int32 net; //for the filtering process

    // Step 1: Open live pcap session on NIC with name "br-f1814131d25c"
    handle = pcap_open_live("br-f1814131d25c", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);
    //Close the handle
    return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {


    // ip header of the received packet (and will be the same for sending)
    struct ip *iph;
    // icmp header of the recieved packet (will be copied with some changes to a new icmp header)
    struct icmp *icmph;
    // a temp struct to hold ip address
    struct in_addr address;
    // set the ip header to it's place in the packet
    iph = (struct ip *) (packet + SIZE_ETHERNET);
    if(iph->ip_p != IPPROTO_ICMP){
        printf("Not an icmp packet!!!\n");
        return;}

    // set the icmp header to it's place in the packet
    icmph = (struct icmp *)(packet + SIZE_ETHERNET + IP4_HDRLEN);
    if(icmph->icmp_type != ICMP_ECHO){
        return;
    }
    // a new icmp header, this one will be the header of the spoofed message)
    struct icmp icmphdr; // ICMP-header
    // the data from the received packet to be echoed
    char *data = (char *)(packet + SIZE_ETHERNET + IP4_HDRLEN + ICMP_HDRLEN);
    // length of icmp  is total length minus the headers
    int datalen = ntohs(iph->ip_len) - ICMP_HDRLEN - IP4_HDRLEN;
    //===================
    // IP header
    //===================
    //swap src and dst
    address = iph->ip_dst;
    iph->ip_dst = iph->ip_src;
    iph->ip_src = address;


    //===================
    // ICMP header
    //===================
    // Message Type (8 bits): ICMP_ECHOREPLY
    icmphdr.icmp_type = ICMP_ECHOREPLY;

    // copy Message Code
    icmphdr.icmp_code = icmph->icmp_code;

    // Identifier (16 bits): copy the number to trace the response.
    icmphdr.icmp_id = icmph->icmp_id;

    // copy Sequence Number (16 bits):
    icmphdr.icmp_seq = icmph->icmp_seq;

    // copy time stamp
    icmphdr.icmp_dun.id_ts = icmph->icmp_dun.id_ts;
    icmphdr.icmp_cksum = 0;

    // Combine the packet
    char packet_out[IP_MAXPACKET];

    // IP header
    memcpy(packet_out, iph, IP4_HDRLEN);

    // ICMP header
    memcpy((packet_out + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);

    // After ICMP header, add the ICMP data.
    memcpy((packet_out + IP4_HDRLEN + ICMP_HDRLEN), data, datalen);

    // Calculate the ICMP header checksum
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (packet_out+IP4_HDRLEN),ICMP_HDRLEN + datalen);
    memcpy((packet_out + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);

    struct sockaddr_in dest_in;
    memset(&dest_in, 0, sizeof(struct sockaddr_in));
    dest_in.sin_family = AF_INET;

    // The port is irrelant for Networking and therefore was zeroed.

    dest_in.sin_addr.s_addr = iph->ip_dst.s_addr;

    // Create raw socket for IP-RAW (make IP-header by yourself)
    int sock = -1;
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        fprintf(stderr, "socket() failed with error: %d", errno);
        fprintf(stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return;
    }
    // set sockopt
    const int flagOne = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &flagOne, sizeof(flagOne)) == -1) {
        fprintf(stderr, "setsockopt failed. error:%d", errno);
        return;
    }
    // Send the packet using sendto() for sending datagrams.
    if (sendto(sock, packet_out, IP4_HDRLEN + ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &dest_in, sizeof(dest_in)) == -1) {
        fprintf(stderr, "sendto() failed with error: %d", errno);

        return;
    } else {
        printf("sent ICMP reply to %s\n", inet_ntoa(iph->ip_dst));
    }
    close(sock);
}
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ctype.h>

#define SIZE_ETHERNET 14

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6];    /* destination host address */
    u_char  ether_shost[6];    /* source host address */
    u_short ether_type;         /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4; // IP header length
    unsigned char      iph_ver:4; // IP version
    unsigned char      iph_tos; // Type of service
    unsigned short int iph_len; // IP Packet length (data + header)
    unsigned short int iph_ident; // Identification
    unsigned short int iph_flag:3; // Fragmentation flags
    unsigned short int iph_offset:13; // Flags offset
    unsigned char      iph_ttl; // Time to Live
    unsigned char      iph_protocol; // Protocol type
    unsigned short int iph_chksum; // IP datagram checksum
    struct in_addr    iph_sourceip; // Source IP address
    struct in_addr    iph_destip;   // Destination IP address
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport; // source port 
    u_short tcp_dport; // destination port
    u_int   tcp_seq; // sequence number
    u_int   tcp_ack; // acknowledgement number 
    u_char  tcp_offx2; // data offset, rsvd
    u_char  tcp_flags;
    u_short tcp_win; // window
    u_short tcp_sum; // checksum
    u_short tcp_urp; // urgent pointer
};

#define TH_OFF(th) (((th)->tcp_offx2 & 0xf0) >> 4)

void print_mac(u_char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader *ip = (struct ipheader *)(packet + SIZE_ETHERNET);

        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader *tcp = (struct tcpheader *)(packet + SIZE_ETHERNET + ip->iph_ihl * 4);

            int ip_header_len = ip->iph_ihl * 4;
            int tcp_header_len = TH_OFF(tcp) * 4;
            int total_headers_size = SIZE_ETHERNET + ip_header_len + tcp_header_len;
            int payload_size = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;

            const u_char *payload = packet + total_headers_size;

            printf("========= New TCP Packet =========\n");
            printf("Src MAC: "); print_mac(eth->ether_shost);
            printf("Dst MAC: "); print_mac(eth->ether_dhost);

            printf("Src IP : %s\n", inet_ntoa(ip->iph_sourceip));
            printf("Dst IP : %s\n", inet_ntoa(ip->iph_destip));
            
            printf("Src Port: %d\n", ntohs(tcp->tcp_sport));
            printf("Dst Port: %d\n", ntohs(tcp->tcp_dport));

            if (payload_size > 0) {
                printf("Payload (%d bytes):\n", payload_size);
                for (int i = 0; i < payload_size && i < 100; i++) {
                    if (isprint(payload[i]))
                        printf("%c", payload[i]);
                    else
                        printf(".");
                }
            } else {
                printf("No Payload.");
            }
            printf("\n==================================\n");
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; 
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF pseudo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);   // Close the handle
    return 0;
}

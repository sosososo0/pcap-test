#include <pcap.h>
#include <libnet.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);

    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {     
        struct pcap_pkthdr *header; 
        const u_char* packet; 

        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        struct libnet_ethernet_hdr *ether = (struct libnet_ethernet_hdr *)packet;
        if (ntohs(ether->ether_type) != ETHERTYPE_IP) continue; // Check if it is an IP packet

        struct libnet_ipv4_hdr *ipv4 = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
        if (ipv4->ip_p != IPPROTO_TCP) continue; // Check if it is a TCP packet

        struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + (ipv4->ip_hl * 4));

        printf("Src MAC : %02x:%02x:%02x:%02x:%02x:%02x , Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", 
            ether->ether_shost[0], ether->ether_shost[1], ether->ether_shost[2], 
            ether->ether_shost[3], ether->ether_shost[4], ether->ether_shost[5],
            ether->ether_dhost[0],ether->ether_dhost[1],ether->ether_dhost[2],
            ether->ether_dhost[3],ether->ether_dhost[4],ether->ether_dhost[5]); 

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ipv4->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipv4->ip_dst), dst_ip, INET_ADDRSTRLEN);

        printf("Src IP : %s ,  Dst IP : %s\n", src_ip, dst_ip);
        printf("Src Port : %d , Dst Port : %d\n", ntohs(tcp->th_sport), ntohs(tcp->th_dport));
        printf("payload : ");
        int data_index = sizeof(ether)+(ipv4->ip_hl * 4)+(tcp->th_off * 4);
        int header_size = header->caplen;
        for(int i=0;i<header_size-data_index;i++){
            if (i==20){
                break;
            }
            else{
            
                printf("0x%02x/",packet[data_index+i]);
            }
        }

        
        printf("\n\n");
    }

    pcap_close(pcap);
    return 0;
}

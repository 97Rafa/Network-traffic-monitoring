#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>


int UDPcount = 0;
int TCPcount = 0;
int flowsC = 0;


/* Finds the payload of a TCP/IP packet */
void my_packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{
    flowsC++;
    printf("\n========    %d    ========\n", flowsC);
    /* First, lets make sure we have an IP packet */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }


    struct ip *ip_h = (struct ip *)(packet + sizeof(struct ether_header));

    if(ip_h->ip_p == IPPROTO_UDP){
        printf("--\tUDP\t--\n");
        UDPcount++;

        printf("Source IP: %s\n", inet_ntoa(ip_h->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ip_h->ip_dst));
        struct udphdr *udp_h = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        printf("Source port: %d\n", ntohs(udp_h->uh_sport));
        printf("Destination port: %d\n", ntohs(udp_h->uh_dport));
        // printf("UDP head length: %d\n", ntohs(udp_h->uh_ulen));
    } else if(ip_h->ip_p == IPPROTO_TCP){
        printf("--\tTCP\t--\n");
        TCPcount++;

        printf("Source IP: %s\n", inet_ntoa(ip_h->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ip_h->ip_dst));
        struct tcphdr *tcp_h = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        printf("Source port: %d\n", ntohs(tcp_h->th_sport));
        printf("Destination port: %d\n", ntohs(tcp_h->th_dport));
        //  ptintf("UDP head length: %d\n", ntohs(tcp_h->)); ====TODO====
    } else{
        printf("Not an UDP/TCP packet. Skipping...\n\n");
        return;
    }

    printf("===     end of %d     ========\n\n", flowsC);
}

int main(int argc, char **argv) {    
    char *device = "eth0";
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    /* Snapshot length is how many bytes to capture from each packet. This includes*/
    int snapshot_length = 1024;
    /* End the loop after this many packets are captured */
    int total_packet_count = 200;
    u_char *my_arguments = NULL;
    
    handle = pcap_open_live(device, snapshot_length, 0, 10000, error_buffer);
    if (handle == NULL) {
                fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
                return 2;
            }    
    // handle = pcap_open_offline("test_pcap_5mins.pcap", error_buffer);
    pcap_loop(handle, 0, my_packet_handler, my_arguments);

    printf("UDP packets: %d\n", UDPcount);
    printf("TCP packets: %d\n", TCPcount);
    printf("Total number of network flows: %d\n", flowsC);

    return 0;
}
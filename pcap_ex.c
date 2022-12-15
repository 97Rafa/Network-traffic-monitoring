#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <signal.h>

struct sigaction old_action;

int UDPcount = 0;
int TCPcount = 0;
int flowsC = 0;
long int UDPbytes = 0;
long int TCPbytes = 0;


void my_packet_handler_OFFLINE(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{
     /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int payload_length;
    int tcp_header_length;
    int udp_header_length;

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

    ip_header_length = ip_h->ip_hl * 4;

    if(ip_h->ip_p == IPPROTO_UDP){
        printf("--\tUDP\t--\n");
        UDPcount++;

        printf("Source IP: %s\n", inet_ntoa(ip_h->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ip_h->ip_dst));
        struct udphdr *udp_h = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_header_length);
        printf("Source port: %d\n", ntohs(udp_h->uh_sport));
        printf("Destination port: %d\n", ntohs(udp_h->uh_dport));
        udp_header_length = ntohs(udp_h->uh_ulen);
        UDPbytes += udp_header_length;
        printf("UDP head length: %lu\n", sizeof(struct udphdr));
        payload_length = header->caplen - (ethernet_header_length + ip_header_length + sizeof(struct udphdr));
        printf("UDP Payload: %d\n", payload_length);
        
    } else if(ip_h->ip_p == IPPROTO_TCP){
        printf("--\tTCP\t--\n");
        TCPcount++;

        printf("Source IP: %s\n", inet_ntoa(ip_h->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ip_h->ip_dst));
        struct tcphdr *tcp_h = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_length);
        printf("Source port: %d\n", ntohs(tcp_h->th_sport));
        printf("Destination port: %d\n", ntohs(tcp_h->th_dport));
        printf("IP head length: %d\n", ip_header_length);
        tcp_header_length = tcp_h->th_off*4;
        TCPbytes += tcp_header_length;
        printf("TCP head length: %d\n", tcp_header_length);
        payload_length = header->caplen - (ethernet_header_length + ip_header_length + tcp_header_length);
        printf("TCP Payload: %d\n", payload_length);
    } else{
        printf("Not an UDP/TCP packet. Skipping...\n\n");
        return;
    }

    printf("===     end of %d     ========\n\n", flowsC);
}


void my_packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{
    FILE *fp;
    
     /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int payload_length;
    int tcp_header_length;
    int udp_header_length;
    fp = fopen("log.txt", "a");
    flowsC++;
    fprintf(fp,"\n========    %d    ========\n", flowsC);
    fclose(fp);
    /* First, lets make sure we have an IP packet */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        fp = fopen("log.txt", "a");
        fprintf(fp,"Not an IP packet. Skipping...\n\n");
        fclose(fp);
        return;
    }


    struct ip *ip_h = (struct ip *)(packet + sizeof(struct ether_header));

    ip_header_length = ip_h->ip_hl * 4;    

    if(ip_h->ip_p == IPPROTO_UDP){
        fp = fopen("log.txt", "a");
        fprintf(fp,"--\tUDP\t--\n");
        UDPcount++;

        fprintf(fp,"Source IP: %s\n", inet_ntoa(ip_h->ip_src));
        fprintf(fp,"Destination IP: %s\n", inet_ntoa(ip_h->ip_dst));
        struct udphdr *udp_h = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_header_length);
        fprintf(fp,"Source port: %d\n", ntohs(udp_h->uh_sport));
        fprintf(fp,"Destination port: %d\n", ntohs(udp_h->uh_dport));
        udp_header_length = ntohs(udp_h->uh_ulen);
        UDPbytes += udp_header_length;
        fprintf(fp,"UDP head length: %lu\n", sizeof(struct udphdr));
        payload_length = header->caplen - (ethernet_header_length + ip_header_length + sizeof(struct udphdr));
        fprintf(fp,"UDP Payload: %d\n", payload_length);
        fclose(fp);
        
    } else if(ip_h->ip_p == IPPROTO_TCP){
        fp = fopen("log.txt", "a");
        fprintf(fp,"--\tTCP\t--\n");
        TCPcount++;

        fprintf(fp,"Source IP: %s\n", inet_ntoa(ip_h->ip_src));
        fprintf(fp,"Destination IP: %s\n", inet_ntoa(ip_h->ip_dst));
        struct tcphdr *tcp_h = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_length);
        fprintf(fp,"Source port: %d\n", ntohs(tcp_h->th_sport));
        fprintf(fp,"Destination port: %d\n", ntohs(tcp_h->th_dport));
        fprintf(fp,"IP head length: %d\n", ip_header_length);
        tcp_header_length = tcp_h->th_off*4;
        TCPbytes += tcp_header_length;
        fprintf(fp,"TCP head length: %d\n", tcp_header_length);
        payload_length = header->caplen - (ethernet_header_length + ip_header_length + tcp_header_length);
        fprintf(fp,"TCP Payload: %d\n", payload_length);
        fclose(fp);
    } else{
        fp = fopen("log.txt", "a");
        fprintf(fp,"Not an UDP/TCP packet. Skipping...\n\n");
        fclose(fp);
        return;
    }
}

void stop_capture()
{
    printf("Total number of network flows captured: %d\n", flowsC);
    printf("Number of UDP network flows captured: %d\n", UDPcount);
    printf("Number of TCP network flows captured: %d\n", TCPcount);
    printf("Total bytes of UDP packets received: %ld\n", UDPbytes);
    printf("Total bytes of TCP packets received: %ld\n", TCPbytes);
}


int main(int argc, char *argv[]) {
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int timeout_limit = 1000; /* In milliseconds */
    char *filter;
    char *interface;
    char *inFile;

    int opt;
    while ((opt = getopt(argc, argv, "i:r:f:h")) != -1) {
        switch (opt) {
        case 'i':   // choose interface
            interface = optarg;
            handle = pcap_open_live(interface,BUFSIZ,0,timeout_limit,error_buffer);
             /* Open device for live capture */
            if (handle == NULL) {
                fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
                return 2;
            }
            pcap_loop(handle, 0, my_packet_handler, NULL);
            break;
        case 'r':   // input file for capturing
            inFile = optarg;
            handle = pcap_open_offline(inFile, error_buffer);
            pcap_loop(handle, 0, my_packet_handler_OFFLINE, NULL);
            break;
        case 'f':   // apply filter
            filter = optarg;
            printf("%s\n", optarg);
            break;
        case 'h':
            printf("i Network interface name (e.g., eth0)\n-r Packet capture file name (e.g., test.pcap)\n-f Filter expression (e.g., port 8080)\n-h Help message\n");
            return 0;
            break;
        default:
            break;
        }
    }
    
    stop_capture();

    return 0;
}
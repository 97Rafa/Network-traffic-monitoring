#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}
void my_packet_handler(u_char *args,const struct pcap_pkthdr *packet_header,const u_char *packet_body)
{
     /* First, lets make sure we have an IP packet */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet_body;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }
    print_packet_info(packet_body, *packet_header);
    return;
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
            break;
        case 'r':   // input file for capturing
            inFile = optarg;
            handle = pcap_open_offline(inFile, error_buffer);
            break;
        case 'f':   // apply filter
            filter = optarg;
            break;
        case 'h':
            printf("i Network interface name (e.g., eth0)\n-r Packet capture file name (e.g., test.pcap)\n-f Filter expression (e.g., port 8080)\n-h Help message\n");
            return 0;
            break;
        default:
            break;
        }
    }
     
    pcap_loop(handle, 0, my_packet_handler, NULL);

    return 0;
}


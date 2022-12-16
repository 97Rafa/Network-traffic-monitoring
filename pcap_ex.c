#include <stdio.h>
#include <stdbool.h>
#include <pcap.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <signal.h>




typedef struct{
    char *srcIP;
    char *dstIP;
    int srcPort;
    int dstPort;
    char *protocol;
}capFlows;

int flowsC = 0;
int UDPflows = 0;
int TCPflows = 0;
int UDPcount = 0;
int TCPcount = 0;
int totalPackets = 0;
long int UDPbytes = 0;
long int TCPbytes = 0;
capFlows *myFlows;
int filter;
bool hasFilter = false;

void my_packet_handler_OFFLINE(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{
    
   
     /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int payload_length;
    int tcp_header_length;
    int udp_header_length;

    totalPackets++;
    /* First, lets make sure we have an IP packet */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }


    struct ip *ip_h = (struct ip *)(packet + sizeof(struct ether_header));
    int sport;
    int dport;
    char *prot=NULL;
    ip_header_length = ip_h->ip_hl * 4;
    uint seqnum;

    if(ip_h->ip_p == IPPROTO_UDP){    
        struct udphdr *udp_h = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_header_length);
        dport = ntohs(udp_h->uh_dport);
        sport = ntohs(udp_h->uh_sport);
        if (hasFilter == true)
        {
            if (filter == sport)
            {
                prot = "UDP";    
                UDPcount++;
                printf("\n========    %d    ========\n", totalPackets);
                printf("--\tUDP\t--\n");
                printf("Source IP: %s\n", inet_ntoa(ip_h->ip_src));
                printf("Destination IP: %s\n", inet_ntoa(ip_h->ip_dst));
                printf("Source port: %d\n", sport);
                printf("Destination port: %d\n", dport);
                udp_header_length = ntohs(udp_h->uh_ulen);
                printf("UDP head length: %lu\n", sizeof(struct udphdr));
                payload_length = header->caplen - (ethernet_header_length + ip_header_length + sizeof(struct udphdr));
                UDPbytes += payload_length;
                printf("UDP Payload: %d\n", payload_length);
                printf("===     end of %d     ========\n\n", totalPackets);
            }
            
        } else {
            prot = "UDP";    
            UDPcount++;
            printf("\n========    %d    ========\n", totalPackets);
            printf("--\tUDP\t--\n");
            printf("Source IP: %s\n", inet_ntoa(ip_h->ip_src));
            printf("Destination IP: %s\n", inet_ntoa(ip_h->ip_dst));
            printf("Source port: %d\n", sport);
            printf("Destination port: %d\n", dport);
            udp_header_length = ntohs(udp_h->uh_ulen);
            printf("UDP head length: %lu\n", sizeof(struct udphdr));
            payload_length = header->caplen - (ethernet_header_length + ip_header_length + sizeof(struct udphdr));
            UDPbytes += payload_length;
            printf("UDP Payload: %d\n", payload_length);
            printf("===     end of %d     ========\n\n", totalPackets);
        }
        
    } else if(ip_h->ip_p == IPPROTO_TCP){
        struct tcphdr *tcp_h = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_length);
        sport = ntohs(tcp_h->th_sport);
        dport = ntohs(tcp_h->th_dport);

        if (hasFilter == true)
        {
            if(filter == sport){
                prot = "TCP";
                TCPcount++;
                printf("\n========    %d    ========\n", totalPackets);
                printf("--\tTCP\t--\n");
                printf("Source IP: %s\n", inet_ntoa(ip_h->ip_src));
                printf("Destination IP: %s\n", inet_ntoa(ip_h->ip_dst));                
                printf("Source port: %d\n", sport);
                printf("Destination port: %d\n", dport);
                printf("IP head length: %d\n", ip_header_length);
                tcp_header_length = tcp_h->th_off*4;
                printf("TCP head length: %d\n", tcp_header_length);
                payload_length = header->caplen - (ethernet_header_length + ip_header_length + tcp_header_length);
                TCPbytes += payload_length;
                printf("TCP Payload: %d\n", payload_length);
                if (tcp_h->seq < tcp_h->ack_seq)
                {
                    printf("!!!\tRETRASMISSION\t!!!\n");
                }
                printf("===     end of %d     ========\n\n", totalPackets);
            }
        }else{
            prot = "TCP";
            TCPcount++;
            printf("\n========    %d    ========\n", totalPackets);
            printf("--\tTCP\t--\n");
            printf("Source IP: %s\n", inet_ntoa(ip_h->ip_src));
            printf("Destination IP: %s\n", inet_ntoa(ip_h->ip_dst));                
            printf("Source port: %d\n", sport);
            printf("Destination port: %d\n", dport);
            printf("IP head length: %d\n", ip_header_length);
            tcp_header_length = tcp_h->th_off*4;
            printf("TCP head length: %d\n", tcp_header_length);
            payload_length = header->caplen - (ethernet_header_length + ip_header_length + tcp_header_length);
            TCPbytes += payload_length;
            printf("TCP Payload: %d\n", payload_length);
            if (tcp_h->seq < tcp_h->ack_seq)
            {
                printf("!!!\tRETRASMISSION\t!!!\n");
            }
            printf("===     end of %d     ========\n\n", totalPackets);
        }

        
    } else{
        printf("Not an UDP/TCP packet. Skipping...\n\n");
        return;
    }

    int alreadySeen = 0;
    for (int i = 0; i < flowsC; i++)
    {   
        if (strcmp(myFlows[i].srcIP,inet_ntoa(ip_h->ip_src)) == 0 && strcmp(myFlows[i].dstIP,inet_ntoa(ip_h->ip_dst)) == 0 && myFlows[i].srcPort == sport && myFlows[i].dstPort == dport)
        {
            alreadySeen = 1;            
            break;
        }
    }

    if (alreadySeen == 0)
    {
        if(prot == "UDP"){
            UDPflows++;
            myFlows = realloc(myFlows, (flowsC+1)*sizeof(capFlows));
            myFlows[flowsC].srcIP=(char *)malloc(INET_ADDRSTRLEN);
            myFlows[flowsC].dstIP=(char *)malloc(INET_ADDRSTRLEN);
            strcpy(myFlows[flowsC].srcIP,inet_ntoa(ip_h->ip_src));
            strcpy(myFlows[flowsC].dstIP,inet_ntoa(ip_h->ip_dst));
            myFlows[flowsC].dstPort = dport;
            myFlows[flowsC].srcPort = sport;
            myFlows[flowsC].protocol = prot;
            flowsC++;
        } else if (prot == "TCP")
        {
            TCPflows++;
            myFlows = realloc(myFlows, (flowsC+1)*sizeof(capFlows));
            myFlows[flowsC].srcIP=(char *)malloc(INET_ADDRSTRLEN);
            myFlows[flowsC].dstIP=(char *)malloc(INET_ADDRSTRLEN);
            strcpy(myFlows[flowsC].srcIP,inet_ntoa(ip_h->ip_src));
            strcpy(myFlows[flowsC].dstIP,inet_ntoa(ip_h->ip_dst));
            myFlows[flowsC].dstPort = dport;
            myFlows[flowsC].srcPort = sport;
            myFlows[flowsC].protocol = prot;
            flowsC++;
        } else {
            return;
        }
        
    }
    
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
    
    totalPackets++;
    
    /* First, lets make sure we have an IP packet */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        fp = fopen("log.txt", "a+");
        fprintf(fp,"Not an IP packet. Skipping...\n\n");
        fclose(fp);
        return;
    }


    struct ip *ip_h = (struct ip *)(packet + sizeof(struct ether_header));
    int sport;
    int dport;
    char *prot;
    ip_header_length = ip_h->ip_hl * 4;    

    if(ip_h->ip_p == IPPROTO_UDP){
        struct udphdr *udp_h = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_header_length);
        dport = ntohs(udp_h->uh_dport);
        sport = ntohs(udp_h->uh_sport);
        if (hasFilter == true)
        {
            if (filter == sport)
            {
                prot = "UDP";
                UDPcount++;
                fp = fopen("log.txt", "a+");
                fprintf(fp,"\n========    %d    ========\n", totalPackets);
                fprintf(fp,"--\tUDP\t--\n");
                fprintf(fp,"Source IP: %s\n", inet_ntoa(ip_h->ip_src));
                fprintf(fp,"Destination IP: %s\n", inet_ntoa(ip_h->ip_dst));
                fprintf(fp,"Source port: %d\n", sport);
                fprintf(fp,"Destination port: %d\n", dport);
                udp_header_length = ntohs(udp_h->uh_ulen);
                UDPbytes += udp_header_length;
                fprintf(fp,"UDP head length: %lu\n", sizeof(struct udphdr));
                payload_length = header->caplen - (ethernet_header_length + ip_header_length + sizeof(struct udphdr));
                fprintf(fp,"UDP Payload: %d\n", payload_length);
                fclose(fp);
            }
            
        } else {
            prot = "UDP";
            UDPcount++;
            fp = fopen("log.txt", "a+");
            fprintf(fp,"\n========    %d    ========\n", totalPackets);
            fprintf(fp,"--\tUDP\t--\n");
            fprintf(fp,"Source IP: %s\n", inet_ntoa(ip_h->ip_src));
            fprintf(fp,"Destination IP: %s\n", inet_ntoa(ip_h->ip_dst));
            fprintf(fp,"Source port: %d\n", sport);
            fprintf(fp,"Destination port: %d\n", dport);
            udp_header_length = ntohs(udp_h->uh_ulen);
            UDPbytes += udp_header_length;
            fprintf(fp,"UDP head length: %lu\n", sizeof(struct udphdr));
            payload_length = header->caplen - (ethernet_header_length + ip_header_length + sizeof(struct udphdr));
            fprintf(fp,"UDP Payload: %d\n", payload_length);
            fclose(fp);
        }
        
    } else if(ip_h->ip_p == IPPROTO_TCP){
        struct tcphdr *tcp_h = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_length);
        dport = ntohs(tcp_h->th_dport);
        sport = ntohs(tcp_h->th_sport);
        if (hasFilter == true)
        {
            if (filter == sport)
            {
                prot = "TCP";
                TCPcount++;
                fp = fopen("log.txt", "a+");
                fprintf(fp,"\n========    %d    ========\n", totalPackets);
                fprintf(fp,"--\tTCP\t--\n");
                fprintf(fp,"Source IP: %s\n", inet_ntoa(ip_h->ip_src));
                fprintf(fp,"Destination IP: %s\n", inet_ntoa(ip_h->ip_dst));
                fprintf(fp,"Source port: %d\n", sport);
                fprintf(fp,"Destination port: %d\n", dport);
                fprintf(fp,"IP head length: %d\n", ip_header_length);
                tcp_header_length = tcp_h->th_off*4;
                TCPbytes += tcp_header_length;
                fprintf(fp,"TCP head length: %d\n", tcp_header_length);
                payload_length = header->caplen - (ethernet_header_length + ip_header_length + tcp_header_length);
                fprintf(fp,"TCP Payload: %d\n", payload_length);
                if (tcp_h->seq < tcp_h->ack_seq)
                {
                    fprintf(fp,"!!!\tRETRASMISSION\t!!!\n");
                }
                fclose(fp);
            }
            
        } else {
            prot = "TCP";
            TCPcount++;
            fp = fopen("log.txt", "a+");
            fprintf(fp,"\n========    %d    ========\n", totalPackets);
            fprintf(fp,"--\tTCP\t--\n");
            fprintf(fp,"Source IP: %s\n", inet_ntoa(ip_h->ip_src));
            fprintf(fp,"Destination IP: %s\n", inet_ntoa(ip_h->ip_dst));
            fprintf(fp,"Source port: %d\n", sport);
            fprintf(fp,"Destination port: %d\n", dport);
            fprintf(fp,"IP head length: %d\n", ip_header_length);
            tcp_header_length = tcp_h->th_off*4;
            TCPbytes += tcp_header_length;
            fprintf(fp,"TCP head length: %d\n", tcp_header_length);
            payload_length = header->caplen - (ethernet_header_length + ip_header_length + tcp_header_length);
            fprintf(fp,"TCP Payload: %d\n", payload_length);
            if (tcp_h->seq < tcp_h->ack_seq)
                {
                    fprintf(fp,"!!!\tRETRASMISSION\t!!!\n");
                }
            fclose(fp);
        }
        
        
    } else{
        fp = fopen("log.txt", "a+");
        fprintf(fp,"Not an UDP/TCP packet. Skipping...\n\n");
        fclose(fp);
        return;
    }
    
    int alreadySeen = 0;
    for (int i = 0; i < flowsC; i++)
    {   
        if (strcmp(myFlows[i].srcIP,inet_ntoa(ip_h->ip_src)) == 0 && strcmp(myFlows[i].dstIP,inet_ntoa(ip_h->ip_dst)) == 0 && myFlows[i].srcPort == sport && myFlows[i].dstPort == dport)
        {
            alreadySeen = 1;            
            break;
        }
    }

    if (alreadySeen == 0)
    {
        if(prot == "UDP"){
            UDPflows++;
            myFlows = realloc(myFlows, (flowsC+1)*sizeof(capFlows));
            myFlows[flowsC].srcIP=(char *)malloc(INET_ADDRSTRLEN);
            myFlows[flowsC].dstIP=(char *)malloc(INET_ADDRSTRLEN);
            strcpy(myFlows[flowsC].srcIP,inet_ntoa(ip_h->ip_src));
            strcpy(myFlows[flowsC].dstIP,inet_ntoa(ip_h->ip_dst));
            myFlows[flowsC].dstPort = dport;
            myFlows[flowsC].srcPort = sport;
            myFlows[flowsC].protocol = prot;
            flowsC++;
        } else if (prot == "TCP")
        {
            TCPflows++;
            myFlows = realloc(myFlows, (flowsC+1)*sizeof(capFlows));
            myFlows[flowsC].srcIP=(char *)malloc(INET_ADDRSTRLEN);
            myFlows[flowsC].dstIP=(char *)malloc(INET_ADDRSTRLEN);
            strcpy(myFlows[flowsC].srcIP,inet_ntoa(ip_h->ip_src));
            strcpy(myFlows[flowsC].dstIP,inet_ntoa(ip_h->ip_dst));
            myFlows[flowsC].dstPort = dport;
            myFlows[flowsC].srcPort = sport;
            myFlows[flowsC].protocol = prot;
            flowsC++;
        } else {
            return;
        }
        
    }
}

void stop_capture()
{
    printf("Total number of network flows captured:\t%d\n", flowsC);
    printf("=======================================\n");
    printf("Number of TCP network flows captured:\t%d\n", TCPflows);
    printf("=======================================\n");
    printf("Number of UDP network flows captured:\t%d\n", UDPflows);
    printf("=======================================\n");
    printf("Total number of packets received:\t%d\n", totalPackets);
    printf("=======================================\n");
    printf("Total number of UDP packets received:\t%d\n", UDPcount);
    printf("=======================================\n");
    printf("Total number of TCP packets received:\t%d\n", TCPcount);
    printf("=======================================\n");
    printf("Total bytes of UDP packets received:\t%ld\n", UDPbytes);
    printf("=======================================\n");
    printf("Total bytes of TCP packets received:\t%ld\n", TCPbytes);
}


int main(int argc, char *argv[]) {
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int timeout_limit = 1000; /* In milliseconds */
    char *interface;
    char *inFile;
    char *arg;
    char *typeOfCap;

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
            typeOfCap = "online";
            break;
        case 'r':   // input file for capturing
            inFile = optarg;
            handle = pcap_open_offline(inFile, error_buffer);
            typeOfCap = "offline";
            break;
        case 'f':   // apply filter
            hasFilter = true;
            arg = strtok(optarg, " ");
            arg = strtok(NULL, " ");
            filter = atoi(arg);
            break;
        case 'h':
            printf("i Network interface name (e.g., eth0)\n-r Packet capture file name (e.g., test.pcap)\n-f Filter expression (e.g., port 8080)\n-h Help message\n");
            break;
        default:
            break;
        }
    }
    if (strcmp(typeOfCap, "online")==0)
    {
        pcap_loop(handle, 0, my_packet_handler, NULL);
    } else {
        pcap_loop(handle, 0, my_packet_handler_OFFLINE, NULL);
    }
    stop_capture();
    return 0;
}
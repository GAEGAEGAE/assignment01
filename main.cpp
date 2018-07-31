#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h> // 이더넷 헤더 구조체
#include <netinet/ip.h>   // 아이피v4 헤더 구조체
#include <netinet/in.h>  
#include <netinet/tcp.h>  // tcp 헤더 
#include <arpa/inet.h>

#define PRINT_MAC "%s - %02x:%02x:%02x:%02x:%02x:%02x\n"  // 맥주소 출력함수 만들기

void usage() {
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

void printMAC(const char* msg, unsigned char* target) {
    printf(PRINT_MAC, msg, target[0], target[1], target[2], target[3], target[4], target[5]);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    int index = 0;

    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0) continue;

        if (res == -1 || res == -2) break;

        printf("\n=================================================\n");
        printf("%u bytes captured\n", header->caplen);

        struct ether_header* eth_header = (ether_header *)packet;
        printMAC("SOURCE MAC", eth_header->ether_shost);
        printMAC("DESTINATION MAC", eth_header->ether_dhost);
        printf("Ethernet TYPE: %04x\n", ntohs(eth_header->ether_type));
        
        packet += sizeof(struct ether_header);
	     index += sizeof(struct ether_header);

        if(ntohs(eth_header->ether_type) == ETHERTYPE_IP) { // 이더타입이 아이피 타입일때만
            struct ip* ip_header = (ip *)packet;
            printf("IP SIP: %s\n", inet_ntoa(ip_header->ip_src));
            printf("IP DIP: %s\n", inet_ntoa(ip_header->ip_dst));

            packet += ip_header->ip_hl * 4;
            index += ip_header->ip_hl * 4;

            if(ip_header->ip_p == IPPROTO_TCP) {    // 아이피 헤더의 타입이 티씨피 일때만
                struct tcphdr* tcp_header = (tcphdr *)packet;
                printf("TCP SPORT: %d\n", ntohs(tcp_header->th_sport));
                printf("TCP DPORT: %d\n", ntohs(tcp_header->th_dport));

                packet += tcp_header->th_off * 4;
		          index += tcp_header->th_off * 4;
               
		          int count = 0;
		          for(int i=index; i < header->caplen; i++) {
        		      printf("%02x|", (int)packet[i]);

        		      if(count!=0 && (count+1) %16 == 0){

             		   printf("\n");
        		      }

			         count++;
                }
            }
        }
    }

    pcap_close(handle);
    return 0;
}

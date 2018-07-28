#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define LOBYTE(x) ((unsigned char)x)
#define HIBYTE(x) ((unsigned short)x >> 8 & 0xFF)

#define MAKEWORD(x, y) ((unsigned char)x | (unsigned short)y << 8)
#define MAKEDWORD(x, y) ((unsigned short)x | (unsigned long)y << 16)



void usage() {
   printf("syntax: pcap_test <interface>\n");
   printf("sample: pcap_test wlan0\n");
}


typedef struct Ethernet_Header // 이더넷 헤더 구조체
{
   u_char desc[6];
   u_char src[6];
   short int ptype;
}Ethernet_Header;


int main(int argc, char* argv[]) {
   if (argc != 2) {
      usage();
      return -1;
   }

   char* dev = argv[1];
   char errbuf[PCAP_ERRBUF_SIZE];

   pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  
   if (handle == NULL) {
      fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
      
      return -1;
   }


   while (true) {
      struct pcap_pkthdr* header;
      
      const u_char* packet;
      int res = pcap_next_ex(handle, &header, &packet);
    
      if (res == 0) {
         continue;
      }

      if (res == -1 || res == -2) {
         break;
      }

      //printf("ETHER TYPE : 0x");

      if(!((int)packet[12] == 0x08 & (int)packet[13] == 0x00 & (int)packet[23] == 6)) {
          continue;
      }

    printf("[PACKET DATA] %u bytes captured\n\n", header->caplen);

    

    // Packet Data Print
    for(int i=0; i < header->caplen; i++) {
        printf("%02x|", packet[i]);

        if(i!=0 && (i+1) %16 == 0){

             printf("\n");
        }
 
    }

    printf("\n\n\n");
 
    printf("Destination MAC ADDRESS : ");

    for(int i=0; i < 6; i++) {
        printf("%02x", packet[i]);

        if(i != 5) {
            printf(":");
        }

        if(i!=0 && (i+1) %16 == 0){

             printf("\n");
        }
 
    }

    printf("\n\n");

    printf("SOURCE MAC ADDRESS : ");

    for(int i=6; i < 12; i++) {
        printf("%02x", packet[i]);

        if(i != 11) {
            printf(":");
        }

        if(i!=0 && (i+1) %16 == 0){

             printf("\n");
        }
 
    }
   
    printf("\n\n");

    printf("ETHER TYPE : 0x");

    for(int i=12; i < 14; i++) {
        printf("%02x", packet[i]);

        if(i!=0 && (i+1) %16 == 0){

             printf("\n");
        }
 
    }


    printf("\n\n");

    printf("SOURCE IP ADDRESS : ");

    for(int i=26; i < 30; i++) {
        printf("%d", packet[i]);
        
        if(i != 29) {
            printf(".");
        }
 
        if(i!=0 && (i+1) %16 == 0){

             printf("\n");
        }
 
    }

    printf("\n\n");
    printf("DESTINATION IP ADDRESS : ");
   

    for(int i=30; i < 34; i++) {
        printf("%d", packet[i]); 

        if(i != 33) {
            printf(".");
        }
    }

    printf("\n\n");

    //해결해야할 문제 _ 각 바이트를 문자열을 합쳐서 해당 문자열을 정수형으로 표현한뒤 10진수로 표현해줘야함 
    printf("SOURCE PORT : ");

    int src_port_num;
    src_port_num = MAKEWORD(packet[35], packet[34]);

    printf("%d", src_port_num);

    /*
    for(int i=34; i < 36; i++) {
        
        printf("%02x", packet[i]); 
    }
    */

    printf("\n\n");

    printf("DESTINATION PORT : ");
    
    int dest_port_num;
    dest_port_num = MAKEWORD(packet[37], packet[36]);

    printf("%d", dest_port_num);
  

    printf("\n\n");

    printf("==============================================================================");
    printf("\n\n");
    
  }

  pcap_close(handle);
  return 0;
}

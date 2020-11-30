#include <stdio.h>
#include <string>
#include <pcap.h>
#include <libnet.h>
#include "mac.h"
#include "tcpBlock.h"
//#include "dumpcode.h"
#define ETHER_HDR_LEN 14

void usage() {
    puts("syntax : tcp-block <interface> <pattern>");
    puts("sample : tcp-block wlan0 \"Host: test.gilgil.net\"");
}

bool includePattern(const u_char* haystack, int hayLen, const char* needle, int needleLen){

    for(int i=0;i<hayLen;i++){
        if(i+needleLen > hayLen){
            break;
        }
        if(memcmp(haystack+i, needle, needleLen)==0){
            return true;
        }
    }

    return false;
}

bool isTarget(const u_char* packet, int pktlen, const char* pattern){
    struct libnet_ethernet_hdr* ethernet_hdr = (libnet_ethernet_hdr*)packet;
    struct libnet_ipv4_hdr* ipv4_hdr = (libnet_ipv4_hdr*)((char*)(ethernet_hdr)+ETHER_HDR_LEN);

    if(ipv4_hdr->ip_p != IPPROTO_TCP){                      //if not TCP, return
        return false;
    }

    uint16_t totalLen = ntohs(*((uint16_t*)ipv4_hdr+1)); 	//caculate the total length of ip packet
    int ipLen = (*((char*)ipv4_hdr)&0x0F)<<2;				//caculate the length of ip header
    struct libnet_tcp_hdr* tcp_hdr = (libnet_tcp_hdr*)((char*)ipv4_hdr+ipLen);

    int tcpLen = ((*((char*)tcp_hdr+12))&0xF0)>>2;  		//caculate the length of tcp header
    const u_char* payload = (u_char*)tcp_hdr + tcpLen;
    
    int payloadLen = totalLen - ipLen - tcpLen;

    if(payloadLen == 0){
        return false;
    }

    return includePattern(payload, payloadLen, pattern, strlen(pattern));
}

int main(int argc, char** argv){
    char* dev;
    char* pattern;
    char errbuf[PCAP_ERRBUF_SIZE];

    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;

    if (argc != 3) {
        usage();
        return -1;
    }

    dev = argv[1];
    pattern = argv[2];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    Mac myMac = getMyMac(dev);
    printf("myMac: %s\n",myMac.operator std::string().c_str());

    while (true) {
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        if(isTarget(packet, header->caplen, pattern)){
			printf("blocking access to %s\n",pattern);
            blockPacket(packet, header->caplen, handle, myMac);
        }
    }
    pcap_close(handle);
}


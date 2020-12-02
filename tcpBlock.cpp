#include <arpa/inet.h>
#include <sys/ioctl.h> 
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <unistd.h>
#include <stdlib.h>
#include <cstdio>
#include <pcap.h>
#include <libnet.h>
#include "mac.h"
#include "ethhdr.h"
#include "tcpBlock.h"

#define ETHER_HDR_LEN 14

Mac getMyMac(const char* ifname){
    struct ifreq ifr;
    int sockfd, ret;
    uint8_t macAddr[6];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        fprintf(stderr, "Fail to get interface MAC address - socket() failed - %m\n");
        exit(0);
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if (ret < 0) {
        fprintf(stderr, "Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
        close(sockfd);
        exit(0);
    }

    close(sockfd);
    
    memcpy(macAddr, ifr.ifr_hwaddr.sa_data, 6);
    return Mac(macAddr);
}

uint16_t getCsum(u_char* data, int len){
    int tmp = 0;
    for(int i=0;i<len;i+=2){
        tmp+=*(uint16_t*)(data+i);
    }
    uint16_t res = tmp&0xFFFF;
    res += (tmp>>16);
    return ~res;
}

uint16_t getTHsum(libnet_ipv4_hdr* ipv4_hdr){

    uint16_t totalLen = ntohs(*((uint16_t*)ipv4_hdr+1)); 	//caculate the total length of ip packet
    int ipLen = (*((char*)ipv4_hdr)&0x0F)<<2;				//caculate the length of ip header
    struct libnet_tcp_hdr* tcp_hdr = (libnet_tcp_hdr*)((char*)ipv4_hdr+ipLen);

	int segmentLen = totalLen - ipLen;								
	int pad = 0;
	if(segmentLen%2!=0){
		pad = 1;
	}
	int dataLen = 12 + segmentLen + pad;

	u_char* data = (u_char*)malloc(dataLen);
	memset(data, 0, dataLen);
	memcpy(data, ((u_char*)ipv4_hdr)+12, 8);
	*((u_int8_t*)(data+9)) = IPPROTO_TCP;
	*((u_int16_t*)(data+10)) = htons(segmentLen);
	memcpy(data+12, (u_char*)(tcp_hdr), segmentLen);

	u_int16_t sum = getCsum(data, dataLen);
	free(data);
	return sum;
}

void blockPacket(const u_char* packet, int pktLen, pcap_t* handle, Mac myMac){

    struct libnet_ethernet_hdr* ethernet_hdr = (libnet_ethernet_hdr*)packet;
	struct libnet_ipv4_hdr* ipv4_hdr = (libnet_ipv4_hdr*)((char*)(ethernet_hdr)+ETHER_HDR_LEN);
    uint16_t totalLen = ntohs(*((uint16_t*)ipv4_hdr+1)); 	//caculate the total length of ip packet
    int ipLen = (*((char*)ipv4_hdr)&0x0F)<<2;				//caculate the length of ip header
	struct libnet_tcp_hdr* tcp_hdr = (libnet_tcp_hdr*)((char*)ipv4_hdr+ipLen);
    int tcpLen = ((*((char*)tcp_hdr+12))&0xF0)>>2;  		//caculate the length of tcp header
    int payloadLen = totalLen - ipLen - tcpLen;

    Mac orgSmac = Mac(ethernet_hdr->ether_shost);
    Mac orgDmac = Mac(ethernet_hdr->ether_dhost);


    u_char *fwdPkt = (u_char*)malloc(54);                   //14 + 20 + 20
    u_char *bwdPkt = (u_char*)malloc(64);                   //14 + 20 + 20 + 10(blocked!)
    memset(fwdPkt, 0, 54);
    memset(bwdPkt, 0, 64);

    //make Forward Packet
    //set Eth header
    ((PEthHdr)fwdPkt)->dmac_ = orgDmac;
    ((PEthHdr)fwdPkt)->smac_ = myMac;
    ((PEthHdr)fwdPkt)->type_ = htons(EthHdr::Ip4);

    //set IP header
    memcpy(fwdPkt+ETHER_HDR_LEN, ipv4_hdr, 20);             //copy org-packet ip header
    ipv4_hdr = (libnet_ipv4_hdr*)((char*)(fwdPkt)+ETHER_HDR_LEN);
    *((char*)ipv4_hdr) = 0x45;                              //IPv4 & hlen: 20
    ipv4_hdr->ip_len = htons(40);							//IP total length
    
    //calculate ip checksum
	ipv4_hdr->ip_sum  = 0;
    ipv4_hdr->ip_sum = getCsum((u_char*)ipv4_hdr, 20);

    //set TCP header
    memcpy(((u_char*)ipv4_hdr)+20, tcp_hdr, 20);                       //copy org-packet tcp header
    tcp_hdr = (libnet_tcp_hdr*)((char*)ipv4_hdr+20);
    tcp_hdr->th_seq = htonl(ntohl(tcp_hdr->th_seq)+payloadLen);
    *((char*)tcp_hdr+12) = 0x50;                            //hlen: 20
    *((char*)tcp_hdr+13) = 0x14;                            //ACk & RST
    
    //calculate TCP checksum
    tcp_hdr->th_sum = 0;
	tcp_hdr->th_sum = getTHsum(ipv4_hdr);
    
    //make Backward Packet
    memcpy(bwdPkt, fwdPkt, 54);
    ((PEthHdr)bwdPkt)->dmac_ = orgSmac;

    ipv4_hdr = (libnet_ipv4_hdr*)((char*)(bwdPkt)+ETHER_HDR_LEN);
    ipv4_hdr->ip_ttl = 128;
    ipv4_hdr->ip_len = htons(50);							//IP total length
    in_addr tmpAddr = ipv4_hdr->ip_src;                     //swap src, dst IP
    ipv4_hdr->ip_src = ipv4_hdr->ip_dst;
    ipv4_hdr->ip_dst = tmpAddr;
    
    //calculate ip checksum
	ipv4_hdr->ip_sum  = 0;
    ipv4_hdr->ip_sum = getCsum((u_char*)ipv4_hdr, 20);

    tcp_hdr = (libnet_tcp_hdr*)((char*)ipv4_hdr+20);
    uint16_t tmpPort = tcp_hdr->th_sport;                   //swap src, dst Port
    tcp_hdr->th_sport = tcp_hdr->th_dport;
    tcp_hdr->th_dport = tmpPort;
    
    int tmp = tcp_hdr->th_seq;                              //swap fwdPkt's ack & seq 
    tcp_hdr->th_seq = tcp_hdr->th_ack; 
    tcp_hdr->th_ack = tmp;

    *((char*)tcp_hdr+13) = 0x11;                            //ACk & FIN

    //TCP data 
    char msg[11] = "blocked!!!";
    memcpy(bwdPkt+54, msg, 10);

	//calculate TCP checksum
    tcp_hdr->th_sum = 0;
	tcp_hdr->th_sum = getTHsum(ipv4_hdr);

    int res = pcap_sendpacket(handle, fwdPkt, 54);
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    free(fwdPkt);
	
    res = pcap_sendpacket(handle, bwdPkt, 64);
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    free(bwdPkt);
}

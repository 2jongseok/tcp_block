#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <libnet.h>

#define TCP_PACKET 1
#define HTTP_PACKET 2
#define FORWARD 0
#define BACKWARD 1
#define MTU 1514

const char * http_method[6]={"GET","POST","DELETE","HEAD","PUT","OPTIONS"};
const char * message = "blocked";

uint8_t my_mac[6];

void Usage() {
  printf("syntax: tcp_block <interface> <host>\n");
  printf("sample: tcp_block wlan0 test.gilgil.net\n");
}

int make_rst_packet(uint8_t* packet, uint32_t seq, uint32_t ack, int direction ){
	struct libnet_ethernet_hdr * ether_header = (struct libnet_ethernet_hdr*) packet;
	struct libnet_ipv4_hdr * ip_header=(struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
	struct libnet_tcp_hdr * tcp_header=(struct libnet_tcp_hdr *)(packet+ sizeof(struct libnet_ethernet_hdr)+ip_header->ip_hl*4);


	if(direction == BACKWARD){
		for(int i=0;i<ETHER_ADDR_LEN;i++)
			ether_header->ether_dhost[i] = ether_header->ether_shost[i];
		uint32_t tmp_ip=ip_header->ip_dst.s_addr;
		uint16_t tmp_port=tcp_header->th_dport;
		ip_header->ip_dst.s_addr=ip_header->ip_src.s_addr;
		ip_header->ip_src.s_addr=tmp_ip;
		tcp_header->th_dport=tcp_header->th_sport;
		tcp_header->th_sport=tmp_port;
	}
	
	for(int i=0;i<ETHER_ADDR_LEN;i++)
		ether_header->ether_shost[i]=my_mac[i];
	ip_header->ip_tos=0x44;
	ip_header->ip_len=htons(ip_header->ip_hl*4+tcp_header->th_off*4);
	ip_header->ip_ttl=0xff;
	ip_header->ip_sum=0;
	tcp_header->th_seq=seq;
	tcp_header->th_ack=ack;
	tcp_header->th_flags&=0;
	tcp_header->th_flags|=TH_RST;
	tcp_header->th_flags|=TH_ACK;
	tcp_header->th_win=0;
	tcp_header->th_sum=0;
	tcp_header->th_urp=0;
}

int make_fin_packet(uint8_t* packet, uint32_t seq, uint32_t ack){
	struct libnet_ethernet_hdr * ether_header=(struct libnet_ethernet_hdr *)packet;
	struct libnet_ipv4_hdr * ip_header = (struct libnet_ipv4_hdr *)(packet +sizeof(struct libnet_ethernet_hdr));
	struct libnet_tcp_hdr * tcp_header=(struct libnet_tcp_hdr *)(packet+sizeof(struct libnet_ethernet_hdr)+ip_header->ip_hl*4);
	uint8_t * data_ptr = (uint8_t*)tcp_header + tcp_header->th_off*4;

	for(int i=0;i<ETHER_ADDR_LEN;i++)
		ether_header->ether_dhost[i]=ether_header->ether_shost[i];
	for(int i=0;i<ETHER_ADDR_LEN;i++)
		ether_header->ether_shost[i]=my_mac[i];
	
	uint32_t tmp_ip = ip_header->ip_dst.s_addr;
	ip_header->ip_dst.s_addr=ip_header->ip_src.s_addr;
	ip_header->ip_src.s_addr=tmp_ip;
	ip_header->ip_tos=0x44;
	ip_header->ip_len=htons(ip_header->ip_hl*4+tcp_header->th_off*4+8);
	ip_header->ip_ttl=0xff;
	ip_header->ip_sum=0;
	
	uint16_t tmp_port=tcp_header->th_dport;
	tcp_header->th_dport=tcp_header->th_sport;
	tcp_header->th_sport=tmp_port;
	tcp_header->th_seq=seq;
	tcp_header->th_ack=ack;
	tcp_header->th_flags&=0;
	tcp_header->th_flags|=TH_FIN;
	tcp_header->th_flags|=TH_ACK;
	tcp_header->th_win=0;
	tcp_header->th_sum=0;
	tcp_header->th_urp=0;
	strncpy((char*)data_ptr, (char*)message, 8);
}

int tcp_block(uint8_t* packet, uint32_t seq, uint32_t ack, uint32_t header_len, uint32_t data_len, pcap_t* handle){
	uint8_t fd_packet[MTU] = {0,}, bk_packet[MTU] = {0,};
	memcpy(fd_packet, packet, MTU);
	memcpy(bk_packet, packet, MTU);
	make_rst_packet(fd_packet, htonl(ntohl(seq)+data_len), ack, FORWARD);
	make_rst_packet(bk_packet, ack, htonl(ntohl(seq)+data_len), BACKWARD);
	pcap_inject(handle, fd_packet, header_len);
	pcap_inject(handle, bk_packet, header_len);
}

int http_block(uint8_t* packet, uint32_t seq, uint32_t ack, uint32_t header_len, uint32_t data_len, pcap_t* handle){
	uint8_t fd_packet[MTU] = {0,}, bk_packet[MTU] = {0,};
	memcpy(fd_packet, packet, MTU);
	memcpy(bk_packet, packet, MTU);
	make_rst_packet(fd_packet, htonl(ntohl(seq)+data_len), ack, FORWARD);
	make_fin_packet(bk_packet, ack, htonl(ntohl(seq)+data_len));
	pcap_inject(handle, fd_packet, header_len);
	pcap_inject(handle, bk_packet, header_len);
}

int packet_check(uint8_t* packet, pcap_t* handle){
	int pkt_type = 0;

	struct libnet_ethernet_hdr * ether_header = (struct libnet_ethernet_hdr*) packet;
	if (ether_header -> ether_type != htons(ETHERTYPE_ARP)) return 0;

	struct libnet_ipv4_hdr * ip_header = (struct libnet_ipv4_hdr*)(ether_header+1);
	int ip_hlen = ip_header->ip_hl*4;
	if(ip_header->ip_p != IPPROTO_TCP) 
		return 0;
	pkt_type = TCP_PACKET;

	struct libnet_tcp_hdr * tcp_header = (struct libnet_tcp_hdr*)((uint8_t*)ip_header + ip_hlen);
	int tcp_hlen = tcp_header->th_off*4;
	uint8_t * data_ptr = (uint8_t*)tcp_header + tcp_header->th_off*4;
	uint32_t header_len = sizeof(struct libnet_ethernet_hdr) + ip_hlen + tcp_hlen;
	uint32_t data_len=(ntohs(ip_header->ip_len)-(ip_hlen+tcp_hlen));
	uint32_t seq=tcp_header->th_seq;
	uint32_t ack=tcp_header->th_ack;
			

	for(int i=0;i<6;i++)
		if(strncmp((char*)data_ptr, (char*)http_method[i], strlen(http_method[i])) == 0)
			pkt_type = HTTP_PACKET;
	if(pkt_type == TCP_PACKET) 
		tcp_block(packet, seq, ack, header_len, data_len, handle);
    else if(pkt_type == HTTP_PACKET) 
    	http_block(packet, seq, ack, header_len, data_len, handle);
	
}

int main(int argc, char * argv[]){
	if(argc != 2){
		Usage();
		return -1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	char * dev = argv[1];

	pcap_t * handle = pcap_open_live(dev,BUFSIZ,1,1,errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	struct ifreq ifrq;
	int soc = socket(AF_INET, SOCK_DGRAM, 0);
	strcpy(ifrq.ifr_name, dev);
	ioctl(soc,SIOCGIFHWADDR, &ifrq);
	for (int i=0; i<ETHER_ADDR_LEN; i++)
		my_mac[i] = ifrq.ifr_hwaddr.sa_data[i];
	close(soc);

	while (true) {
  		struct pcap_pkthdr* header;
  		const u_char* packet;
    	int res = pcap_next_ex(handle, &header, &packet);
    	if (res == 0) 
    		continue;
    	if (res == -1 || res == -2){
  			pcap_close(handle);
  			return 0;
    	}
    	packet_check((uint8_t*)packet, handle);  	
  }
  return 0;
}


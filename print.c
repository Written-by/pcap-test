#include "print.h"

void print_eth(eth_hdr* eth){
	printf("Ethernet Header: \n");
	printf("-src mac: %s\n", ether_ntoa((eth_hdr*) eth->ether_shost));
	printf("-dst mac: %s\n", ether_ntoa((eth_hdr*) eth->ether_dhost));
	return;
}

void print_ip(ipv4_hdr* ip){
	printf("IP Header: \n");
	printf("-src ip: %s\n", inet_ntoa(ip->ip_src));
	printf("-dst ip: %s\n", inet_ntoa(ip->ip_dst));
	return;
}

void print_tcp(tcp_hdr* tcp){
	printf("TCP Header: \n");
	printf("-src port: %u\n", ntohs(tcp->th_sport));
	printf("-dst port: %u\n", ntohs(tcp->th_dport));
	return;
}

void print_payload(eth_hdr* eth, ipv4_hdr* ip, tcp_hdr* tcp){
	printf("Payload(Data): \n");
	printf("-hexadecimal value(up to 8 bytes): ");
	uint8_t* payload=(uint8_t*)tcp+((uint8_t)tcp->th_off<<2);
	uint16_t size=ntohs(ip->ip_len)-((uint16_t)ip->ip_hl<<2)-((uint16_t)tcp->th_off<<2);
	if(size>8) size=8;
	for(uint16_t i=0; i<size; i++) printf("0x%x ", payload[i]);
	printf("\n");
	return;
}

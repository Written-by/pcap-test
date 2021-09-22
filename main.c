#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "print.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		eth_hdr* eth=(eth_hdr*)packet;
		ipv4_hdr* ip=(ipv4_hdr*)(packet+sizeof(eth_hdr));
		tcp_hdr* tcp=(tcp_hdr*)(packet+sizeof(eth_hdr)+sizeof(ipv4_hdr));
		printf("Captured Packet:\n");
		if(ntohs(eth->ether_type)==ETHERTYPE_IP&&ip->ip_p==IPPROTO_TCP){
			print_eth(eth);
			print_ip(ip);
			print_tcp(tcp);
			print_payload(eth,ip,tcp);
		}else printf("not a TCP packet\n");
	}

	pcap_close(pcap);
	return 0;
}


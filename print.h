#pragma once
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/ether.h>
#include <libnet.h>

typedef struct libnet_ethernet_hdr eth_hdr;
typedef struct libnet_ipv4_hdr ipv4_hdr;
typedef struct libnet_tcp_hdr tcp_hdr;

void print_eth(eth_hdr* eth);
void print_ip(ipv4_hdr* ip);
void print_tcp(tcp_hdr* tcp);
void print_payload(eth_hdr* eth, ipv4_hdr* ip, tcp_hdr* tcp);

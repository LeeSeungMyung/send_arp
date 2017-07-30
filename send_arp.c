#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>

#include "libnet-headers.h"


#define IPV4_ADDR_LEN 4
#define PCAP_OPENFLAG_PROMISCUOUS 1

struct send_arp_addr {
	uint8_t  senderHA[ETHER_ADDR_LEN];
	uint32_t senderIP;
	uint8_t  targetHA[ETHER_ADDR_LEN];
	uint32_t targetIP;
} __attribute__((packed)); //disabled padding;

int send_arp(const char* interface,const uint16_t operation, const char* target_ip, pcap_t *handle){
	struct ifreq ifr;
	struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
	struct libnet_ethernet_hdr ether_header;
	struct libnet_arp_hdr arp_header;
	struct send_arp_addr arp_addr;

	const size_t ether_header_size = sizeof(struct libnet_ethernet_hdr);
	const size_t arp_header_size = sizeof(struct libnet_arp_hdr);
	const size_t arp_addr_size = sizeof(struct send_arp_addr);
	const int s = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	
	size_t packet_size;

	size_t i;
	char *ip;
	uint8_t *packet;

	strncpy(ifr.ifr_name, interface, IFNAMSIZ);
	
	if(ioctl(s, SIOCGIFHWADDR, &ifr) != 0){
		perror( "ioctl() SIOCGIFHWADDR error"); 
		exit(1);
	}
	
    for (i = 0; i < 6; ++i)
		printf("%02x:", (unsigned char)ifr.ifr_addr.sa_data[i]);
	puts("");

	packet_size = ether_header_size + arp_header_size + arp_addr_size;
	packet = (uint8_t*)calloc(1, packet_size);

	memset(ether_header.ether_dhost, 0xff, ETHER_ADDR_LEN);
	memmove(ether_header.ether_shost, ifr.ifr_addr.sa_data, ETHER_ADDR_LEN);
	ether_header.ether_type = htons(ETHERTYPE_ARP);

	arp_header.ar_hrd = htons(ARPHRD_ETHER);
	arp_header.ar_pro = htons(ETHERTYPE_IP);
	arp_header.ar_hln = ETHER_ADDR_LEN;
	arp_header.ar_pln = IPV4_ADDR_LEN;
	arp_header.ar_op  = htons(operation);

	memmove(arp_addr.senderHA, ifr.ifr_addr.sa_data, ETHER_ADDR_LEN);

	if(ioctl(s, SIOCGIFADDR, &ifr) != 0){
		perror("ioctl() SIOCGIFADDR error");
		exit(1);
	}

	arp_addr.senderIP = sin->sin_addr.s_addr;
	memset(arp_addr.targetHA, 0x00, ETHER_ADDR_LEN);
	inet_aton(target_ip, (struct in_addr*)(&arp_addr.targetIP));
	
	memmove(packet, &ether_header, ether_header_size);
	memmove(packet+ether_header_size, &arp_header, arp_header_size);
	memmove(packet+ether_header_size+arp_header_size, &arp_addr, arp_addr_size);

	pcap_sendpacket(handle, packet, packet_size);
	for(i = 0; i < packet_size; i++){
		printf("%02x ", packet[i]);
		if( i==10)	puts("");
	}
	puts("");

	ip = inet_ntoa(sin->sin_addr);
	printf("%s\n", ip);


	return 0;

}
int main (int argc, char *argv[])
{
    pcap_t *handle;         /* Session handle */
    char *dev;          /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    struct bpf_program fp;      /* The compiled filter */
    char filter_exp[] = "port 80";  /* The filter expression */
    bpf_u_int32 mask;       /* Our netmask */
    bpf_u_int32 net;        /* Our IP */
    struct pcap_pkthdr *header; /* The header that pcap gives us */
    const uint8_t *packet;      /* The actual packet */
    int i;
    int s = socket (PF_INET, SOCK_STREAM, 0);
	
	if(argc != 4){
		puts("argc != 4");
		return 1;
	}

    dev = argv[1]; //get interface

    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) { //filter
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) { //port 80 set
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }


	
	send_arp(argv[1], ARPOP_REQUEST, argv[3], handle);

	

    close (s);
    return 0;
}


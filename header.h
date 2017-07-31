#pragma once
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


/* define */
#define IPV4_ADDR_LEN 4
#define PCAP_OPENFLAG_PROMISCUOUS 1


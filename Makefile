all: send_arp

send_arp: send_arp.c
	gcc -o send_arp send_arp.c -lpcap -W -Wall


clean:
	rm send_arp

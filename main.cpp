#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

//#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14
struct sniff_ethernet{
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)
struct sniff_ip{
	u_char ip_vhl, ip_tos;
	u_short ip_len, ip_id, ip_off;
	u_char ip_ttl, ip_p;
	u_short ip_sum;

	struct in_addr ip_src, ip_dst;
};

#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
struct sniff_tcp{
	u_short th_sport, th_dport;
	tcp_seq th_seq, th_ack;
	u_char th_offx2, th_flags;
	u_short th_win, th_sum, th_urp;
};

void usage()
{
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

void printEthernetHeader(const u_char *packet, u_short *ether_type)
{
	struct sniff_ethernet *ethernet = (struct sniff_ethernet*)packet;
	*ether_type = ethernet->ether_type;

	printf("src mac : ");
	for(int i=0; i<ETHER_ADDR_LEN; i++)
		printf("%02x ", ethernet->ether_shost[i]);
	printf("\n");

	printf("dst mac : ");
	for(int i=0; i<ETHER_ADDR_LEN; i++)
		printf("%02x ", ethernet->ether_dhost[i]);
	printf("\n");
}

void printIPHeader(const u_char *packet, u_int *size_ip, u_short *ip_len, u_char *ip_p)
{
	struct sniff_ip *ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	*size_ip = IP_HL(ip)*4;
	*ip_len = ip->ip_len;
	*ip_p = ip->ip_p;
	
	printf("src ip : %s\n", inet_ntoa(ip->ip_src));
	printf("dst ip : %s\n", inet_ntoa(ip->ip_dst));
}

void printTCPHeader(const u_char *packet, u_int size_ip, u_int *size_tcp)
{
	struct sniff_tcp *tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	*size_tcp = TH_OFF(tcp)*4;

	printf("src port : %d\n", ntohs(tcp->th_sport));
	printf("dst port : %d\n", ntohs(tcp->th_dport));
}

void printPayload(const u_char *packet, u_int size_ip, u_short ip_len, u_int size_tcp)
{
	u_char *payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	int payload_len = ntohs(ip_len) - (size_ip + size_tcp);
	printf("Payload Data : ");
	for(int i=0; i<payload_len-1 && i<16; i++)
		printf("%02x ", payload[i]);
	printf("\n");
}

int main(int argc, char* argv[])
{
	if(argc != 2){
		usage();
		return -1;
	}

	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL){
		fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
		return -1;
	}

	while(true){
		struct pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if(res == 0) continue;
		if(res == -1 || res == -2){
			printf("pacap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		printf("----------------------------------------\n");
		u_int size_ip, size_tcp;
		u_short ip_len, ether_type;
		u_char ip_p;
		printEthernetHeader(packet, &ether_type);
//		printf("ether_type : %04x\n", ether_type);
		if(ether_type == 0x0008){
			printIPHeader(packet, &size_ip, &ip_len, &ip_p);
			if(ip_p == 0x06){
				printTCPHeader(packet, size_ip, &size_tcp);
				printPayload(packet, size_ip, ip_len, size_tcp);
			}
		}
		printf("----------------------------------------\n");
	}

	pcap_close(handle);

	
	return 0;
}

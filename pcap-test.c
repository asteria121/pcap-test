#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6
#define LIBNET_LIL_ENDIAN 1

#define IPV4VAL 0x0800
#define TCPVAL 0x06

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */
#endif
    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,        /* data offset */
           th_x2:4;         /* (unused) */
#endif
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
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

bool IsIPv4TCP(const char* packet)
{
        u_int16_t ipv4Type = ntohs(((struct libnet_ethernet_hdr*)(packet))->ether_type);
        u_int8_t protocol = ((struct libnet_ipv4_hdr*)(sizeof(struct libnet_ethernet_hdr) + packet))->ip_p;

        return (ipv4Type == IPV4VAL) && (protocol == TCPVAL);
}

void PrintMAC(const char* packet)
{
        u_int8_t* srcMac = ((struct libnet_ethernet_hdr*)packet)->ether_shost;
        u_int8_t* dstMac = ((struct libnet_ethernet_hdr*)packet)->ether_dhost;

        printf("Src MAC: %02X:%02X:%02X:%02X:%02X:%02X, ", srcMac[0], srcMac[1], srcMac[2], srcMac[3], srcMac[4], srcMac[5]);
        printf("Dst MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", dstMac[0], dstMac[1], dstMac[2], dstMac[3], dstMac[4], dstMac[5]);
}

void PrintIP(const char* packet)
{
        // inet_ntoa() returns static buffer
        char* ip = inet_ntoa(((struct libnet_ipv4_hdr*)(sizeof(struct libnet_ethernet_hdr) + packet))->ip_src);
	printf("Src IP: %s, ", ip);
	inet_ntoa(((struct libnet_ipv4_hdr*)(sizeof(struct libnet_ethernet_hdr) + packet))->ip_dst);
	printf("Dst IP: %s\n", ip);
}

void PrintPort(const char* packet)
{
        struct libnet_tcp_hdr* tcpHdr = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));
        
        u_int16_t sport = ntohs(tcpHdr->th_sport);
        u_int16_t dport = ntohs(tcpHdr->th_dport);
        printf("Src Port: %d, Dst Port: %d\n", sport, dport);
}

void PrintData(const char* packet, u_int16_t packetLen)
{
        // TCP Header may contain options field. So get header size manually.
        u_int16_t tcpHeaderLen = ((struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr)))->th_off * 4;
        
        // Calculate data offset
        u_int16_t dataOffset = sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + tcpHeaderLen;
        
        // Calculate data len
        u_int16_t dataLen = packetLen - dataOffset;
        
        printf("Packet data (%u Bytes)\n", dataLen);
        u_int16_t i;
        for (i = 0; i < 20 && i < dataLen; i++)
        {
                printf("%02X ", (u_int8_t)(*(packet + dataOffset + i)));
        }
        printf("\n");
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
		
		if (IsIPv4TCP(packet))
		{
		        PrintMAC(packet);
		        PrintIP(packet);
		        PrintPort(packet);
		        PrintData(packet, header->caplen);
		        printf("\n");
		}
	}

	pcap_close(pcap);
	
	return 0;
}

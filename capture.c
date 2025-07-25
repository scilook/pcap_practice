#define _GNU_SOURCE
#include <pcap.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

typedef struct s_pcap_log
{
	struct timeval first_ts;
	struct timeval last_ts;
	long long packets;
	long long bytes;
	// For simplified RTT: store SYN timestamp
	struct timeval syn_ts;
	int syn_seen;
	int syn_ack_seen;
	double rtt; // Round Trip Time in milliseconds
} t_pcap_log; // 필요시 수정

pcap_t	*g_handle;

static void pcap_callback(u_char *pcap_log, const struct pcap_pkthdr *header, const u_char *bytes);

static void signal_handler(int signum)
{
	printf("\n[SIGNAL] SIGINT received, stopping capture...\n");
	if (g_handle) {
		pcap_breakloop(g_handle);
	}
}

static void print_summary(t_pcap_log pcap_log) {
	double duration = (pcap_log.last_ts.tv_sec - pcap_log.first_ts.tv_sec) * 1000.0; // s to ms
	duration += (pcap_log.last_ts.tv_usec - pcap_log.first_ts.tv_usec) / 1000.0; // us to ms

	double throughput_kbps = 0;
	if (duration > 0)
		throughput_kbps = (pcap_log.bytes * 8) / (duration / 1000.0) / 1000.0; // kbps

	printf("\n=== TCP Session Analysis Report ===\n");
	printf("Total packets captured: %lld\n", pcap_log.packets);
	printf("Total bytes captured: %lld\n", pcap_log.bytes);
	printf("Session duration: %.2f ms\n", duration);
	printf("Average throughput: %.2f kbps\n", throughput_kbps);
	if (pcap_log.rtt > 0) {
		printf("Initial RTT (SYN->SYN/ACK): %.3f ms\n", pcap_log.rtt);
	} else {
		printf("Initial RTT: Not captured (handshake not observed)\n");
	}
	printf("=====================================\n");
}

int main(int argc, char *argv[])
{
	t_pcap_log pcap_log;
	struct bpf_program fp;
	char errbuf[PCAP_ERRBUF_SIZE];

	signal(SIGINT, signal_handler);
	pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf);
	g_handle = pcap_create("any", errbuf);
	pcap_activate(g_handle);
	pcap_compile(g_handle, &fp, "tcp", 0, PCAP_NETMASK_UNKNOWN);
	pcap_loop(g_handle, -1, pcap_callback, (u_char *)&pcap_log);
	if (pcap_log.packets > 0)
		print_summary(pcap_log);
	else
		printf("\n[INFO] No packets were captured.\n");
	pcap_freecode(&fp);
	pcap_close(g_handle);
	return 0;
}


//demo

// IP 헤더 구조체 정의
struct ip_header {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

// TCP 헤더 구조체 정의
struct tcp_header {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    u_int th_seq;                   /* sequence number */
    u_int th_ack;                   /* acknowledgement number */
    u_char th_offx2;                /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};

static void pcap_callback(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet)
{
	t_pcap_log *log = (t_pcap_log *)user_data;

	if (log->packets == 0) {
		log->first_ts = header->ts;
		printf("[INFO] First packet captured at %ld.%06ld\n", 
		       header->ts.tv_sec, (long)header->ts.tv_usec);
		printf("[INFO] Starting packet analysis...\n");
	}
	log->last_ts = header->ts;
	log->packets++;

	// Calculate time since start
	double time_since_start = (header->ts.tv_sec - log->first_ts.tv_sec) * 1000.0;
	time_since_start += (header->ts.tv_usec - log->first_ts.tv_usec) / 1000.0;

	// Parse Ethernet header
	struct ether_header *eth_header = (struct ether_header *)packet;
	if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
		// Not an IP packet, skip
		return;
	}

	// Parse IP header
	struct ip_header *ip_header = (struct ip_header *)(packet + sizeof(struct ether_header));
	int ip_header_len = (ip_header->ip_vhl & 0x0f) * 4;
	if (ip_header->ip_p != IPPROTO_TCP) {
		// Not a TCP packet, skip
		return;
	}
	
	// Parse TCP header
	struct tcp_header *tcp_header = (struct tcp_header *)(packet + sizeof(struct ether_header) + ip_header_len);
	int tcp_header_len = TH_OFF(tcp_header) * 4;
	int payload_len = ntohs(ip_header->ip_len) - ip_header_len - tcp_header_len;
	if (payload_len > 0) {
		log->bytes += payload_len;
	}

	// Print packet info for demonstration
	printf("[%6.2f ms] [PACKET %lld] TCP %s:%d -> %s:%d, Payload: %d bytes, Flags: ",
	       time_since_start,
	       log->packets,
	       inet_ntoa(ip_header->ip_src), ntohs(tcp_header->th_sport),
	       inet_ntoa(ip_header->ip_dst), ntohs(tcp_header->th_dport),
	       payload_len);
	
	if (tcp_header->th_flags & TH_SYN) printf("SYN ");
	if (tcp_header->th_flags & TH_ACK) printf("ACK ");
	if (tcp_header->th_flags & TH_FIN) printf("FIN ");
	if (tcp_header->th_flags & TH_RST) printf("RST ");
	if (tcp_header->th_flags & TH_PUSH) printf("PSH ");
	if (tcp_header->th_flags & TH_URG) printf("URG ");
	printf("\n");

	// Show payload preview for interesting packets
	if (payload_len > 0) {
		const u_char *payload = packet + sizeof(struct ether_header) + ip_header_len + tcp_header_len;
		printf("[PAYLOAD] First 32 bytes: ");
		for (int i = 0; i < payload_len && i < 32; i++) {
			if (payload[i] >= 32 && payload[i] <= 126) {
				printf("%c", payload[i]);
			} else {
				printf(".");
			}
		}
		printf("\n");
	}

	// Simplified RTT calculation for the first handshake
	if (!log->syn_seen && tcp_header->th_flags & TH_SYN && !(tcp_header->th_flags & TH_ACK)) {
		log->syn_ts = header->ts;
		log->syn_seen = 1;
		printf("[RTT] SYN packet detected, storing timestamp\n");
	} else if (log->syn_seen && !log->syn_ack_seen && (tcp_header->th_flags & (TH_SYN | TH_ACK))) {
		log->syn_ack_seen = 1;
		double syn_time = log->syn_ts.tv_sec * 1000.0 + log->syn_ts.tv_usec / 1000.0;
		double syn_ack_time = header->ts.tv_sec * 1000.0 + header->ts.tv_usec / 1000.0;
		log->rtt = syn_ack_time - syn_time;
		printf("[RTT] SYN/ACK packet detected, RTT calculated: %.3f ms\n", log->rtt);
	}
}
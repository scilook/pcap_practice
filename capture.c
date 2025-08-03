#include "capture.h"


static void pcap_callback(u_char *pcap_log, const struct pcap_pkthdr *header, const u_char *packet);

static void signal_handler(int signum);

void print_rtt(struct pcap_pkthdr header, const u_char *packet)
{
	static double time = (header.ts.tv_sec * 1000 * 1000 + header.ts.tv_usec) / 1000;
	double throughput_kbps = 0;
	if (duration > 0)
	throughput_kbps = (pcap_log.bytes * 8) / (duration / 1000.0) / 1000.0; // kbps
	
		if (pcap_log.rtt > 0) {
		printf("Initial RTT (SYN->SYN/ACK): %.3f ms\n", pcap_log.rtt);
	} else {
		printf("Initial RTT: Not captured (handshake not observed)\n");
	}
}

static void print_summary(t_pcap_log pcap_log) {
	printf("\n=== TCP Session Summary ===\n");
	printf("Session: %s:%s <-> %s:%s\n", LOCAL_IP, LOCAL_PORT, SERVER_IP, SERVER_PORT);
	printf("Total packets: %d\n", pcap_log.packets_cnt);
	printf("Data Transferred: %d MB\n", pcap_log.size);
	printf("Avg RTT: %.1f ms\n", );
	printf("Retransmissions: %d", pcap_log.retrans_cnt);
	printf("=====================================\n");
}

pcap_t	*g_handle;

// 1. 특정 세션의 통계
// 2. 모든 통신을 분류하여 세션별 통계
int main(int argc, char *argv[])
{
	t_pcap_log pcap_log;
	t_dev dev;
	struct bpf_program fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *filter;

	signal(SIGINT, signal_handler);
	dev.name = pcap_lookupdev(errbuf);

	pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf);
	g_handle = pcap_create(dev.name, errbuf);
	pcap_activate(g_handle);
	filter = filter_express(&dev, errbuf);
	pcap_compile(g_handle, &fp, filter, 0, dev.net);
	pcap_loop(g_handle, -1, pcap_callback, (u_char *)&pcap_log);
	if (pcap_log.packets_cnt > 0)
		print_summary(pcap_log);
	else
		printf("\n[INFO] No packets were captured.\n");
	pcap_freecode(&fp);
	pcap_close(g_handle);
	return 0;
}

static void signal_handler(int signum)
{
	printf("\n[SIGNAL] SIGINT received, stopping capture...\n");
	if (g_handle) {
		pcap_breakloop(g_handle);
	}
}

static char *filter_express(t_dev *dev, char *errbuf)
{
	pcap_lookupnet(dev->name, &(dev->net), &(dev->mask), errbuf);
	char filter[256];
	sprintf(filter,
			"tcp and ((src host %s and src port %s and dst host %s and dst port %s) "
			"or (src host %s and src port %s and dst host %s and dst port %s))",
			LOCAL_IP, LOCAL_PORT, SERVER_IP, SERVER_PORT,
			SERVER_IP, SERVER_PORT, LOCAL_IP, LOCAL_PORT);
	return filter;
}

/* static void pcap_callback(u_char *pcap_log, const struct pcap_pkthdr *header, const u_char *packet)
{

} */


//demo

// IP 헤더 구조체 정의
// struct ip_header {
// 	u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
// 	u_char  ip_tos;                 /* type of service */
// 	u_short ip_len;                 /* total length */
// 	u_short ip_id;                  /* identification */
// 	u_short ip_off;                 /* fragment offset field */
// 	u_char  ip_ttl;                 /* time to live */
// 	u_char  ip_p;                   /* protocol */
// 	u_short ip_sum;                 /* checksum */
// 	struct  in_addr ip_src,ip_dst;  /* source and dest address */
// };

// TCP 헤더 구조체 정의
// struct tcp_header {
// 	u_short th_sport;               /* source port */
// 	u_short th_dport;               /* destination port */
// 	u_int th_seq;                   /* sequence number */
// 	u_int th_ack;                   /* acknowledgement number */
// 	u_char th_offx2;                /* data offset, rsvd */
// #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
// 	u_char th_flags;
// #define TH_FIN  0x01
// #define TH_SYN  0x02
// #define TH_RST  0x04
// #define TH_PUSH 0x08
// #define TH_ACK  0x10
// #define TH_URG  0x20
// #define TH_ECE  0x40
// #define TH_CWR  0x80
// 	u_short th_win;                 /* window */
// 	u_short th_sum;                 /* checksum */
// 	u_short th_urp;                 /* urgent pointer */
// };

static void pcap_callback(u_char *pcap_log, const struct pcap_pkthdr *header, const u_char *packet)
{
	t_pcap_log *log = (t_pcap_log *)pcap_log;

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
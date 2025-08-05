#include "capture.h"

static void pcap_callback(u_char *pcap_log, const struct pcap_pkthdr *header, const u_char *packet);

static void signal_handler(int signum);

static void print_summary(t_pcap_log pcap_log) {
	double total_rtt = 0;
	int rtt_count = 0;

	t_list *current = pcap_log.rtt_list;
	while (current)
	{
		total_rtt += (double)(intptr_t)current->content;
		rtt_count++;
		current = current->next;
	}
	printf("\n=== TCP Session Summary ===\n");
	printf("Session: %s:%s <-> %s:%s\n", LOCAL_IP, LOCAL_PORT, SERVER_IP, SERVER_PORT);
	printf("Total packets: %d\n", pcap_log.packets_cnt);
	printf("Data Transferred: %d MB\n", pcap_log.size);
	printf("Avg RTT: %.1f ms\n", rtt_count > 0 ? total_rtt / rtt_count : 0);
	printf("Retransmissions: %d", pcap_log.retrans_cnt);
	printf("=====================================\n");
}

void pcap_log_init(t_pcap_log *log)
{
	log->rtt_list = lst_init(NULL);
	log->packets_cnt = 0;
	log->retrans_cnt = 0;
	log->size = 0;
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

	pcap_log_init(&pcap_log);
	signal(SIGINT, signal_handler);
	//pcap_findalldevs(&dev.name, errbuf);

	pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf);
	g_handle = pcap_create("any", errbuf);
	pcap_activate(g_handle);
	pcap_compile(g_handle, &fp, "tcp", 0, dev.net);
	pcap_loop(g_handle, -1, pcap_callback, (u_char *)&pcap_log);
	if (pcap_log.packets_cnt > 0)
		print_summary(pcap_log);
	else
		printf("\n[INFO] No packets were captured.\n");
	pcap_freecode(&fp);
	//pcap_freealldevs(dev.name);
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

/* 	헤더 내용
	ts, caplen, len
		- ts: 패킷 캡처 시간
		- caplen: 캡처된 패킷의 길이
		- len: 실제 패킷의 길이
	패킷 내용
	tcp 헤더, IP 헤더, 이더넷 헤더 */
static void pcap_callback(u_char *pcap_log, const struct pcap_pkthdr *header, const u_char *packet)
{
	t_pcap_log *log = (t_pcap_log *)pcap_log;
	log->packets_cnt++;
	log->size += header->len;

	// 이더넷 헤더 확인
	t_ether_header *eth_header = (t_ether_header *)packet;
	if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
		return;
	// IP 헤더 파싱
	t_ip_header *ip_header = (t_ip_header *)(packet + sizeof(t_ether_header));
	int ip_header_len = (ip_header->version_ihl & 0x0f) * 4;
	if (ip_header->protocol != IPPROTO_TCP)
		return;
	// TCP 헤더 파싱
	t_tcp_header *tcp_header = (t_tcp_header *)(packet + sizeof(t_ether_header) + ip_header_len);
	int tcp_header_len = (tcp_header->data_offset >> 4) * 4;
	int payload_len = ntohs(ip_header->total_length) - ip_header_len - tcp_header_len;
	if (payload_len < 0)
		return;
	// TCP 플래그 확인
	uint8_t flags = tcp_header->flags;
	if (flags & TH_RST) {
		log->retrans_cnt++;
		printf("[RETRANSMISSION] RST flag detected in packet from %s:%d to %s:%d\n",
			   inet_ntoa(ip_header->src_addr), ntohs(tcp_header->src_port),
			   inet_ntoa(ip_header->dst_addr), ntohs(tcp_header->dst_port));
	}
	// RTT 계산 (SYN -> SYN/ACK)
	if (flags & TH_SYN) {
		struct timeval syn_time = header->ts;
		printf("[HANDSHAKE] SYN packet from %s:%d to %s:%d\n",
			   inet_ntoa(ip_header->src_addr), ntohs(tcp_header->src_port),
			   inet_ntoa(ip_header->dst_addr), ntohs(tcp_header->dst_port));
		if (flags & TH_ACK) {
			double rtt = (header->ts.tv_sec - syn_time.tv_sec) * 1000.0 +
				(header->ts.tv_usec - syn_time.tv_usec) / 1000.0;
			printf("[HANDSHAKE] SYN/ACK received, RTT: %.3f ms\n", rtt);
			log->rtt_list = lst_add_front(&log->rtt_list, (void *)(intptr_t)rtt);
		}
	}
	if (flags & TH_FIN || flags & TH_RST) {
		printf("[SESSION_END] Session %s:%d <-> %s:%d closed\n",
			   inet_ntoa(ip_header->src_addr), ntohs(tcp_header->src_port),
			   inet_ntoa(ip_header->dst_addr), ntohs(tcp_header->dst_port));
	}
}

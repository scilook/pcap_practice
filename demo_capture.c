#include "capture.h"

// 전역 변수
t_list *session_list = NULL;         // 세션 연결 리스트
pcap_t *g_handle = NULL;

// 함수 선언
void signal_handler(int signum);
void pcap_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
t_tcp_session* find_or_create_session(t_session_key *key);
void process_packet(t_tcp_session *session, const struct pcap_pkthdr *header, 
				   const struct ip *ip_hdr, const struct tcphdr *tcp_hdr, int payload_len);
void add_seq_entry(t_list **list, u_int seq_num, struct timeval timestamp, char direction);
double calculate_rtt(t_list **list, u_int ack_num, struct timeval current_time);
void detect_retransmission(t_tcp_session *session, u_int seq_num, char direction);
void print_session_summary(t_tcp_session *session);
void print_all_sessions();
void cleanup_sessions();
t_session_key create_session_key(const struct ip *ip_hdr, const struct tcphdr *tcp_hdr);

int main(int argc, char *argv[]) {
	char errbuf[PCAP_ERRBUF_SIZE];
	char *device;
	struct bpf_program fp;
	bpf_u_int32 net, mask;

	// 신호 핸들러 등록
	signal(SIGINT, signal_handler);

	// 네트워크 디바이스 찾기
	device = pcap_lookupdev(errbuf);
	if (device == NULL) {
		fprintf(stderr, "Error finding device: %s\n", errbuf);
		return 1;
	}

	printf("Using device: %s\n", device);

	// 네트워크 정보 가져오기
	if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Error getting network info: %s\n", errbuf);
		net = 0;
		mask = 0;
	}

	// pcap 핸들 생성
	g_handle = pcap_open_live(device, BUFSIZ, 1, 65536, errbuf);
	if (g_handle == NULL) {
		fprintf(stderr, "Error opening device: %s\n", errbuf);
		return 1;
	}

	// TCP 필터 설정
	char filter_exp[] = "tcp";
	if (pcap_compile(g_handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(g_handle));
		return 1;
	}

	if (pcap_setfilter(g_handle, &fp) == -1) {
		fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(g_handle));
		return 1;
	}

	printf("Starting TCP session monitoring...\n");
	printf("Press Ctrl+C to stop and view summary\n\n");

	// 패킷 캡처 시작
	pcap_loop(g_handle, -1, pcap_callback, NULL);

	// 정리 작업
	pcap_freecode(&fp);
	pcap_close(g_handle);
	print_all_sessions();
	cleanup_sessions();

	return 0;
}

void signal_handler(int signum) {
	printf("\n\n[SIGNAL] SIGINT received, stopping capture...\n");
	if (g_handle) {
		pcap_breakloop(g_handle);
	}
}

// 세션 키 생성 함수
t_session_key create_session_key(const struct ip *ip_hdr, const struct tcphdr *tcp_hdr) {
	t_session_key key;
	
	// 양방향 통신을 같은 세션으로 인식하기 위해 정규화
	// 작은 IP:Port를 src로, 큰 IP:Port를 dst로 설정
	uint32_t ip1 = ntohl(ip_hdr->ip_src.s_addr);
	uint32_t ip2 = ntohl(ip_hdr->ip_dst.s_addr);
	uint16_t port1 = ntohs(tcp_hdr->th_sport);
	uint16_t port2 = ntohs(tcp_hdr->th_dport);

	if (ip1 < ip2 || (ip1 == ip2 && port1 < port2)) {
		strcpy(key.src_ip, inet_ntoa(ip_hdr->ip_src));
		strcpy(key.dst_ip, inet_ntoa(ip_hdr->ip_dst));
		key.src_port = port1;
		key.dst_port = port2;
	} else {
		strcpy(key.src_ip, inet_ntoa(ip_hdr->ip_dst));
		strcpy(key.dst_ip, inet_ntoa(ip_hdr->ip_src));
		key.src_port = port2;
		key.dst_port = port1;
	}
	
	return key;
}

// 세션 찾기 또는 새로 생성
t_tcp_session* find_or_create_session(t_session_key *key) {
	t_list *current = session_list;
	
	// 기존 세션 찾기
	while (current != NULL) {
		t_tcp_session *session = (t_tcp_session *)current->content;
		if (strcmp(session->src_ip, key->src_ip) == 0 &&
			strcmp(session->dst_ip, key->dst_ip) == 0 &&
			session->src_port == key->src_port &&
			session->dst_port == key->dst_port) {
			return session;
		}
		current = current->next;
	}
	
	// 새 세션 생성
	t_tcp_session *new_session = calloc(1, sizeof(t_tcp_session));
	if (new_session == NULL) {
		fprintf(stderr, "Memory allocation failed\n");
		return NULL;
	}
	
	// 세션 초기화
	strcpy(new_session->src_ip, key->src_ip);
	strcpy(new_session->dst_ip, key->dst_ip);
	new_session->src_port = key->src_port;
	new_session->dst_port = key->dst_port;
	
	// 리스트에 추가
	session_list = lst_add_front(&session_list, new_session);
	
	printf("[NEW SESSION] %s:%d <-> %s:%d\n", 
		   new_session->src_ip, new_session->src_port,
		   new_session->dst_ip, new_session->dst_port);
	
	return new_session;
}

// SEQ 엔트리 추가 함수
void add_seq_entry(t_list **list, u_int seq_num, struct timeval timestamp, char direction) {
	t_seq_entry *new_entry = malloc(sizeof(t_seq_entry));
	if (new_entry == NULL) return;
	
	new_entry->seq_num = seq_num;
	new_entry->timestamp = timestamp;
	new_entry->direction = direction;
	
	*list = lst_add_front(list, new_entry);
}

// RTT 계산 함수
double calculate_rtt(t_list **list, u_int ack_num, struct timeval current_time) {
	t_list *current = *list;
	t_list *prev = NULL;
	
	while (current != NULL) {
		t_seq_entry *seq_entry = (t_seq_entry *)current->content;
		if (seq_entry->seq_num == ack_num) {
			// RTT 계산
			double rtt = (current_time.tv_sec - seq_entry->timestamp.tv_sec) * 1000.0;
			rtt += (current_time.tv_usec - seq_entry->timestamp.tv_usec) / 1000.0;
			
			// 리스트에서 제거
			if (prev) {
				prev->next = current->next;
			} else {
				*list = current->next;
			}
			free(seq_entry);
			free(current);
			
			return rtt;
		}
		prev = current;
		current = current->next;
	}
	
	return -1; // RTT 계산 실패
}

// 재전송 탐지 함수
void detect_retransmission(t_tcp_session *session, u_int seq_num, char direction) {
	t_list *current = session->seen_seqs;
	
	while (current != NULL) {
		t_seq_entry *seq_entry = (t_seq_entry *)current->content;
		if (seq_entry->seq_num == seq_num && seq_entry->direction == direction) {
			session->retrans_count++;
			printf("[RETRANSMISSION] SEQ %u (%c) detected in session %s:%d <-> %s:%d\n",
				   seq_num, direction, session->src_ip, session->src_port,
				   session->dst_ip, session->dst_port);
			return;
		}
		current = current->next;
	}
	
	// 새로운 SEQ 번호 추가
	add_seq_entry(&session->seen_seqs, seq_num, (struct timeval){0, 0}, direction);
}

// 패킷 처리 함수
void process_packet(t_tcp_session *session, const struct pcap_pkthdr *header,
				   const struct ip *ip_hdr, const struct tcphdr *tcp_hdr, int payload_len) {
	
	// 패킷 카운트 및 바이트 카운트 업데이트
	session->total_packets++;
	if (payload_len > 0) {
		session->total_bytes += payload_len;
		
		// 첫 번째 데이터 패킷 시간 기록
		if (!session->has_data) {
			session->first_data_time = header->ts;
			session->has_data = 1;
		}
		// 마지막 데이터 패킷 시간 업데이트
		session->last_data_time = header->ts;
	}
	
	// TCP 플래그 처리
	u_char flags = tcp_hdr->th_flags;
	
	// SYN 패킷 처리 (연결 시작)
	if (flags & TH_SYN && !(flags & TH_ACK)) {
		if (!session->syn_seen) {
			session->syn_seen = 1;
			session->syn_time = header->ts;
			printf("[HANDSHAKE] SYN detected for session %s:%d <-> %s:%d\n",
				   session->src_ip, session->src_port, session->dst_ip, session->dst_port);
		}
	}
	
	// SYN+ACK 패킷 처리
	if ((flags & TH_SYN) && (flags & TH_ACK)) {
		if (session->syn_seen && !session->syn_ack_seen) {
			session->syn_ack_seen = 1;
			session->conn_rtt = (header->ts.tv_sec - session->syn_time.tv_sec) * 1000.0;
			session->conn_rtt += (header->ts.tv_usec - session->syn_time.tv_usec) / 1000.0;
			
			// RTT 평균 계산을 위한 누적
			session->total_rtt += session->conn_rtt;
			session->rtt_count++;
			
			printf("[HANDSHAKE] SYN+ACK detected, Connection RTT: %.3f ms\n", session->conn_rtt);
		}
	}
	
	// ACK 패킷 처리
	if (flags & TH_ACK) {
		if (session->syn_ack_seen && !session->established) {
			session->established = 1;
			printf("[HANDSHAKE] Connection established for session %s:%d <-> %s:%d\n",
				   session->src_ip, session->src_port, session->dst_ip, session->dst_port);
		}
		
		// 데이터 RTT 계산
		double data_rtt = calculate_rtt(&session->pending_seqs, ntohl(tcp_hdr->th_ack), header->ts);
		if (data_rtt > 0) {
			// RTT 평균 계산을 위한 누적
			session->total_rtt += data_rtt;
			session->rtt_count++;
		}
	}
	
	// FIN 패킷 처리 (연결 종료)
	if (flags & TH_FIN || flags & TH_RST) {
		if (!session->session_closed) {
			session->session_closed = 1;
			printf("[SESSION_END] Session %s:%d <-> %s:%d closed\n",
				   session->src_ip, session->src_port, session->dst_ip, session->dst_port);
			
			if (session->has_data && session->total_bytes > 0) {
				double duration = (session->last_data_time.tv_sec - session->first_data_time.tv_sec) +
								 (session->last_data_time.tv_usec - session->first_data_time.tv_usec) / 1000000.0;
				
				if (duration > 0) {
					printf("[SESSION_END] Throughput: %.2f bytes/sec\n", 
						   (double)session->total_bytes / duration);
				} else {
					printf("[SESSION_END] Throughput: N/A (instantaneous transfer)\n");
				}
			} else {
				printf("[SESSION_END] Throughput: N/A (no data transferred)\n");
			}
		}
	}
	
	// 데이터가 있는 패킷의 경우 SEQ 번호 추가 (RTT 계산용)
	// 방향 판단: 소스 IP가 세션의 src_ip와 같으면 클라이언트->서버('C'), 아니면 서버->클라이언트('S')
	if (payload_len > 0) {
		char direction = (strcmp(inet_ntoa(ip_hdr->ip_src), session->src_ip) == 0) ? 'C' : 'S';
		add_seq_entry(&session->pending_seqs, ntohl(tcp_hdr->th_seq), header->ts, direction);
		detect_retransmission(session, ntohl(tcp_hdr->th_seq), direction);
	}
}

// pcap 콜백 함수
void pcap_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	// 이더넷 헤더 확인
	struct ether_header *eth_header = (struct ether_header *)packet;
	if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
		return;
	}
	
	// IP 헤더 파싱
	struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
	int ip_header_len = (ip_hdr->ip_hl) * 4;
	
	if (ip_hdr->ip_p != IPPROTO_TCP) {
		return;
	}
	
	// TCP 헤더 파싱
	struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_len);
	int tcp_header_len = (tcp_hdr->th_off) * 4;
	int payload_len = ntohs(ip_hdr->ip_len) - ip_header_len - tcp_header_len;
	
	// 세션 키 생성 및 세션 찾기/생성
	t_session_key key = create_session_key(ip_hdr, tcp_hdr);
	t_tcp_session *session = find_or_create_session(&key);
	
	if (session == NULL) {
		return;
	}
	
	// 패킷 처리
	process_packet(session, header, ip_hdr, tcp_hdr, payload_len);
}

// 세션 요약 출력 함수
void print_session_summary(t_tcp_session *session) {
	printf("\n===== Session Summary =====\n");
	printf("Session: %s:%d <-> %s:%d\n", 
		   session->src_ip, session->src_port, 
		   session->dst_ip, session->dst_port);
	printf("Total Packets: %d\n", session->total_packets);
	if ((double)session->total_bytes / (1024 * 1024) > 1)
		printf("Data Transferred: %.2f MB\n", (double)session->total_bytes / (1024 * 1024));
	else if ((double)session->total_bytes / 1024 > 1)
		printf("Data Transferred: %.2f KB\n", (double)session->total_bytes / 1024);
	else
		printf("Data Transferred: %lld Bytes\n", session->total_bytes);

	// Avg RTT: Connect RTT 및 모든 data RTT 평균
	if (session->rtt_count > 0) {
		double avg_rtt = session->total_rtt / session->rtt_count;
		printf("Avg RTT: %.1f ms\n", avg_rtt);
	}
	
	printf("Retransmissions: %d\n", session->retrans_count);
	printf("===========================\n");
}

// 모든 세션 출력
void print_all_sessions() {
	t_list *current = session_list;
	int session_count = 0;
	
	printf("\n\n======= TCP SESSION ANALYSIS SUMMARY =======\n");
	
	while (current != NULL) {
		session_count++;
		t_tcp_session *session = (t_tcp_session *)current->content;
		print_session_summary(session);
		current = current->next;
	}
	
	printf("\nTotal Sessions Monitored: %d\n", session_count);
	printf("============================================\n");
}

// 메모리 정리 함수
void cleanup_sessions() {
	t_list *current = session_list;
	
	while (current != NULL) {
		t_list *next = current->next;
		t_tcp_session *session = (t_tcp_session *)current->content;
		
		// SEQ 리스트 정리
		lst_clear(&session->pending_seqs);
		lst_clear(&session->seen_seqs);
		
		free(session);
		free(current);
		current = next;
	}
	session_list = NULL;
}
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
#include <time.h>

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

// 세션 식별을 위한 4-튜플 구조체
typedef struct {
    char src_ip[16];
    char dst_ip[16];
    unsigned short src_port;
    unsigned short dst_port;
} session_key_t;

// SEQ 번호와 타임스탬프를 저장하는 구조체 (RTT 계산용)
typedef struct seq_entry {
    u_int seq_num;
    struct timeval timestamp;
    struct seq_entry *next;
} seq_entry_t;

// 1초별 처리율 계산을 위한 구조체
typedef struct throughput_entry {
    time_t second;
    long bytes;
    struct throughput_entry *next;
} throughput_entry_t;

// 각 TCP 세션을 식별하고 추적하기 위한 구조체
typedef struct tcp_session {
    char src_ip[16];                 // 출발지 IP
    char dst_ip[16];                 // 목적지 IP
    unsigned short src_port;         // 출발지 포트
    unsigned short dst_port;         // 목적지 포트

    // RTT 계산용 변수
    double conn_rtt;                 // 연결 수립 RTT (3-way handshake)
    double latest_data_rtt;          // 최근 데이터 RTT
    seq_entry_t *pending_seqs;       // 대기 중인 SEQ 번호들 (RTT 계산용)
    
    // 핸드셰이크 추적
    int syn_seen;
    struct timeval syn_time;
    int syn_ack_seen;
    int established;

    // 처리율 계산용 변수
    long long total_bytes;           // 총 전송 바이트
    struct timeval first_packet_time; // 세션 첫 패킷 시간
    struct timeval last_packet_time;  // 세션 마지막 패킷 시간
    throughput_entry_t *throughput_list; // 1초별 처리율 저장

    // 재전송 탐지용 변수
    int retrans_count;               // 재전송 카운트
    seq_entry_t *seen_seqs;          // 이미 확인된 SEQ 번호들

    int total_packets;               // 총 패킷 수
    int session_closed;              // 세션 종료 상태

    struct tcp_session *next;        // 연결 리스트용 포인터
} tcp_session_t;

// 전역 변수
tcp_session_t *session_list = NULL;  // 세션 연결 리스트
pcap_t *g_handle = NULL;

// 함수 선언
void signal_handler(int signum);
void pcap_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
tcp_session_t* find_or_create_session(session_key_t *key);
void process_packet(tcp_session_t *session, const struct pcap_pkthdr *header, 
                   const struct ip_header *ip_hdr, const struct tcp_header *tcp_hdr, int payload_len);
void add_seq_entry(seq_entry_t **list, u_int seq_num, struct timeval timestamp);
double calculate_rtt(seq_entry_t **list, u_int ack_num, struct timeval current_time);
void update_throughput(tcp_session_t *session, int bytes, struct timeval timestamp);
void detect_retransmission(tcp_session_t *session, u_int seq_num);
void print_session_summary(tcp_session_t *session);
void print_all_sessions();
void cleanup_sessions();
session_key_t create_session_key(const struct ip_header *ip_hdr, const struct tcp_header *tcp_hdr);

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
    g_handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
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
session_key_t create_session_key(const struct ip_header *ip_hdr, const struct tcp_header *tcp_hdr) {
    session_key_t key;
    
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
tcp_session_t* find_or_create_session(session_key_t *key) {
    tcp_session_t *current = session_list;
    
    // 기존 세션 찾기
    while (current != NULL) {
        if (strcmp(current->src_ip, key->src_ip) == 0 &&
            strcmp(current->dst_ip, key->dst_ip) == 0 &&
            current->src_port == key->src_port &&
            current->dst_port == key->dst_port) {
            return current;
        }
        current = current->next;
    }
    
    // 새 세션 생성
    tcp_session_t *new_session = malloc(sizeof(tcp_session_t));
    if (new_session == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    
    // 세션 초기화
    memset(new_session, 0, sizeof(tcp_session_t));
    strcpy(new_session->src_ip, key->src_ip);
    strcpy(new_session->dst_ip, key->dst_ip);
    new_session->src_port = key->src_port;
    new_session->dst_port = key->dst_port;
    
    // 리스트에 추가
    new_session->next = session_list;
    session_list = new_session;
    
    printf("[NEW SESSION] %s:%d <-> %s:%d\n", 
           new_session->src_ip, new_session->src_port,
           new_session->dst_ip, new_session->dst_port);
    
    return new_session;
}

// SEQ 엔트리 추가 함수
void add_seq_entry(seq_entry_t **list, u_int seq_num, struct timeval timestamp) {
    seq_entry_t *new_entry = malloc(sizeof(seq_entry_t));
    if (new_entry == NULL) return;
    
    new_entry->seq_num = seq_num;
    new_entry->timestamp = timestamp;
    new_entry->next = *list;
    *list = new_entry;
}

// RTT 계산 함수
double calculate_rtt(seq_entry_t **list, u_int ack_num, struct timeval current_time) {
    seq_entry_t *current = *list;
    seq_entry_t *prev = NULL;
    
    while (current != NULL) {
        if (current->seq_num == ack_num) {
            // RTT 계산
            double rtt = (current_time.tv_sec - current->timestamp.tv_sec) * 1000.0;
            rtt += (current_time.tv_usec - current->timestamp.tv_usec) / 1000.0;
            
            // 리스트에서 제거
            if (prev) {
                prev->next = current->next;
            } else {
                *list = current->next;
            }
            free(current);
            
            return rtt;
        }
        prev = current;
        current = current->next;
    }
    
    return -1; // RTT 계산 실패
}

// 처리율 업데이트 함수
void update_throughput(tcp_session_t *session, int bytes, struct timeval timestamp) {
    time_t current_second = timestamp.tv_sec;
    
    // 현재 초에 해당하는 엔트리 찾기
    throughput_entry_t *current = session->throughput_list;
    while (current != NULL) {
        if (current->second == current_second) {
            current->bytes += bytes;
            return;
        }
        current = current->next;
    }
    
    // 새로운 초 엔트리 생성
    throughput_entry_t *new_entry = malloc(sizeof(throughput_entry_t));
    if (new_entry == NULL) return;
    
    new_entry->second = current_second;
    new_entry->bytes = bytes;
    new_entry->next = session->throughput_list;
    session->throughput_list = new_entry;
}

// 재전송 탐지 함수
void detect_retransmission(tcp_session_t *session, u_int seq_num) {
    seq_entry_t *current = session->seen_seqs;
    
    while (current != NULL) {
        if (current->seq_num == seq_num) {
            session->retrans_count++;
            printf("[RETRANSMISSION] SEQ %u detected in session %s:%d <-> %s:%d\n",
                   seq_num, session->src_ip, session->src_port,
                   session->dst_ip, session->dst_port);
            return;
        }
        current = current->next;
    }
    
    // 새로운 SEQ 번호 추가
    add_seq_entry(&session->seen_seqs, seq_num, (struct timeval){0, 0});
}

// 패킷 처리 함수
void process_packet(tcp_session_t *session, const struct pcap_pkthdr *header,
                   const struct ip_header *ip_hdr, const struct tcp_header *tcp_hdr, int payload_len) {
    
    // 첫 번째 패킷인 경우 시간 기록
    if (session->total_packets == 0) {
        session->first_packet_time = header->ts;
    }
    session->last_packet_time = header->ts;
    session->total_packets++;
    
    // 바이트 카운트 업데이트
    if (payload_len > 0) {
        session->total_bytes += payload_len;
        update_throughput(session, payload_len, header->ts);
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
            session->latest_data_rtt = data_rtt;
        }
    }
    
    // FIN 패킷 처리 (연결 종료)
    if (flags & TH_FIN || flags & TH_RST) {
        if (!session->session_closed) {
            session->session_closed = 1;
            printf("[SESSION_END] Session %s:%d <-> %s:%d closed\n",
                   session->src_ip, session->src_port, session->dst_ip, session->dst_port);
        }
    }
    
    // 데이터가 있는 패킷의 경우 SEQ 번호 추가 (RTT 계산용)
    if (payload_len > 0) {
        add_seq_entry(&session->pending_seqs, ntohl(tcp_hdr->th_seq), header->ts);
        detect_retransmission(session, ntohl(tcp_hdr->th_seq));
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
    struct ip_header *ip_hdr = (struct ip_header *)(packet + sizeof(struct ether_header));
    int ip_header_len = (ip_hdr->ip_vhl & 0x0f) * 4;
    
    if (ip_hdr->ip_p != IPPROTO_TCP) {
        return;
    }
    
    // TCP 헤더 파싱
    struct tcp_header *tcp_hdr = (struct tcp_header *)(packet + sizeof(struct ether_header) + ip_header_len);
    int tcp_header_len = TH_OFF(tcp_hdr) * 4;
    int payload_len = ntohs(ip_hdr->ip_len) - ip_header_len - tcp_header_len;
    
    // 세션 키 생성 및 세션 찾기/생성
    session_key_t key = create_session_key(ip_hdr, tcp_hdr);
    tcp_session_t *session = find_or_create_session(&key);
    
    if (session == NULL) {
        return;
    }
    
    // 패킷 처리
    process_packet(session, header, ip_hdr, tcp_hdr, payload_len);
}

// 세션 요약 출력 함수
void print_session_summary(tcp_session_t *session) {
    printf("\n===== Session Summary =====\n");
    printf("Session: %s:%d <-> %s:%d\n", 
           session->src_ip, session->src_port, 
           session->dst_ip, session->dst_port);
    printf("Total Packets: %d\n", session->total_packets);
    printf("Data Transferred: %.2f MB\n", (double)session->total_bytes / (1024 * 1024));
    
    if (session->conn_rtt > 0) {
        printf("Connection RTT: %.1f ms\n", session->conn_rtt);
    }
    if (session->latest_data_rtt > 0) {
        printf("Latest Data RTT: %.1f ms\n", session->latest_data_rtt);
    }
    
    printf("Retransmissions: %d\n", session->retrans_count);
    
    // 전체 세션 시간 계산
    if (session->total_packets > 0) {
        double duration = (session->last_packet_time.tv_sec - session->first_packet_time.tv_sec) * 1000.0;
        duration += (session->last_packet_time.tv_usec - session->first_packet_time.tv_usec) / 1000.0;
        
        if (duration > 0) {
            double avg_throughput = (session->total_bytes * 8.0) / (duration / 1000.0) / 1000.0; // kbps
            printf("Average Throughput: %.2f Kbps\n", avg_throughput);
        }
    }
    
    // 최대 1초당 처리율 계산
    long max_bytes_per_sec = 0;
    throughput_entry_t *current = session->throughput_list;
    while (current != NULL) {
        if (current->bytes > max_bytes_per_sec) {
            max_bytes_per_sec = current->bytes;
        }
        current = current->next;
    }
    
    if (max_bytes_per_sec > 0) {
        printf("Peak Throughput: %.2f Kbps\n", (max_bytes_per_sec * 8.0) / 1000.0);
    }
    
    printf("Status: %s\n", session->session_closed ? "Closed" : "Active");
    printf("=========================\n");
}

// 모든 세션 출력
void print_all_sessions() {
    tcp_session_t *current = session_list;
    int session_count = 0;
    
    printf("\n\n======= TCP SESSION ANALYSIS SUMMARY =======\n");
    
    while (current != NULL) {
        session_count++;
        print_session_summary(current);
        current = current->next;
    }
    
    printf("\nTotal Sessions Monitored: %d\n", session_count);
    printf("============================================\n");
}

// 메모리 정리 함수
void cleanup_sessions() {
    tcp_session_t *current = session_list;
    
    while (current != NULL) {
        tcp_session_t *next = current->next;
        
        // SEQ 리스트 정리
        seq_entry_t *seq_current = current->pending_seqs;
        while (seq_current != NULL) {
            seq_entry_t *seq_next = seq_current->next;
            free(seq_current);
            seq_current = seq_next;
        }
        
        seq_current = current->seen_seqs;
        while (seq_current != NULL) {
            seq_entry_t *seq_next = seq_current->next;
            free(seq_current);
            seq_current = seq_next;
        }
        
        // 처리율 리스트 정리
        throughput_entry_t *thr_current = current->throughput_list;
        while (thr_current != NULL) {
            throughput_entry_t *thr_next = thr_current->next;
            free(thr_current);
            thr_current = thr_next;
        }
        
        free(current);
        current = next;
    }
}
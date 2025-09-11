#ifndef CAPTURE_H
# define CAPTURE_H

# define _GNU_SOURCE
# include <pcap.h>
# include <stdio.h>
# include <unistd.h>
# include <stdlib.h>
# include <string.h>
# include <signal.h>
# include <sys/types.h>
# include <arpa/inet.h>
# include <net/ethernet.h>
# include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <time.h>

typedef struct s_list
{
	void *content;
	struct s_list *next;
} t_list;

// 세션 식별을 위한 4-튜플 구조체
typedef struct s_session_key {
	char src_ip[16];
	char dst_ip[16];
	unsigned short src_port;
	unsigned short dst_port;
} t_session_key;

// SEQ 번호와 타임스탬프를 저장하는 구조체 (RTT 계산용)
typedef struct s_seq_entry {
	u_int seq_num;
	struct timeval timestamp;
	char direction;  // 'C' for client->server, 'S' for server->client
} t_seq_entry;

// 각 TCP 세션을 식별하고 추적하기 위한 구조체
typedef struct s_tcp_session {
	char src_ip[16];                 // 출발지 IP
	char dst_ip[16];                 // 목적지 IP
	unsigned short src_port;         // 출발지 포트
	unsigned short dst_port;         // 목적지 포트

	// RTT 계산용 변수
	double conn_rtt;                 // 연결 수립 RTT (3-way handshake)
	double total_rtt;                // 모든 RTT 합계 (conn_rtt + data_rtt들)
	int rtt_count;                   // RTT 측정 횟수
	t_list *pending_seqs;            // 대기 중인 SEQ 번호들 (RTT 계산용)
	
	// 핸드셰이크 추적
	int syn_seen;
	struct timeval syn_time;
	int syn_ack_seen;
	int established;

	// 세션 통계
	long long total_bytes;           // 총 전송 바이트
	struct timeval first_data_time;  // 첫 번째 데이터 패킷 시간
	struct timeval last_data_time;   // 마지막 데이터 패킷 시간
	int has_data;                    // 데이터 패킷이 있는지 여부

	// 재전송 탐지용 변수
	int retrans_count;               // 재전송 카운트
	t_list *seen_seqs;               // 이미 확인된 SEQ 번호들

	int total_packets;               // 총 패킷 수
	int session_closed;              // 세션 종료 상태
} t_tcp_session;

typedef struct s_dev
{
	pcap_if_t *name;
	bpf_u_int32 net;
	bpf_u_int32 mask;
} t_dev;

typedef struct s_pcap_log
{
	t_list *rtt_list;
	int packets_cnt;
	int retrans_cnt;
	int size;
} t_pcap_log;

t_list *lst_init(void *content);
t_list *lst_add_front(t_list **lst, void *content);
t_list *lst_add_rear(t_list **lst, void *content);
void lst_clear(t_list **lst);

#endif /* CAPTURE_H */
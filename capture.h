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

// 세션 식별 정보 구조체
typedef struct s_session_key {
	char src_ip[16];
	char dst_ip[16];
	unsigned short src_port;
	unsigned short dst_port;
} t_session_key;

// SEQ 번호와 타임스탬프를 저장하는 구조체
typedef struct s_seq_entry {
	u_int seq_num;
	struct timeval timestamp;
} t_seq_entry;

// TCP 세션 추적 구조체
typedef struct s_tcp_session {
	char src_ip[16];
	char dst_ip[16];
	unsigned short src_port;
	unsigned short dst_port;

	// RTT 계산 변수
	double total_rtt;
	int rtt_count;
	t_list *pending_seqs;			// 대기 중인 SEQ 번호들
	
	// 핸드셰이크 추적
	int syn_seen;
	struct timeval syn_time;
	int syn_ack_seen;
	int established;

	// 처리율 계산 변수
	long long total_bytes;
	struct timeval first_data_time;
	struct timeval last_data_time;

	// 재전송 탐지 변수
	int retrans_count;
	t_list *seen_seqs;				// 이미 확인된 SEQ 번호들

	int total_packets;
	int session_closed;
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
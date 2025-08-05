#ifndef CAPTURE_H
# define CAPTURE_H

// #define LOCAL_IP		"LOCALHOST"
// #define LOCAL_PORT		"5050"
// #define SERVER_IP		"203.0.113.50"
// #define SERVER_PORT		"80"

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

typedef struct s_ether_header
{
	u_char ether_dhost[6];        // Destination MAC address
	u_char ether_shost[6];        // Source MAC address
	u_short ether_type;           // EtherType field
} t_ether_header;

typedef struct s_ip_header
{
	uint8_t version_ihl;
	uint8_t type_of_service;
	uint16_t total_length;
	uint16_t identification;
	uint16_t flags_fragment_offset;
	uint8_t time_to_live;
	uint8_t protocol;
	uint16_t header_checksum;
	struct in_addr src_addr;
	struct in_addr dst_addr;
} t_ip_header;

typedef struct s_tcp_header
{
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_num;
	uint32_t ack_num;
	uint8_t data_offset;
	uint8_t flags;
	uint16_t window_size;
	uint16_t checksum;
	uint16_t urgent_pointer;
} t_tcp_header;

typedef struct s_list
{
	void *content;
	struct s_list *next;
} t_list;

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

#endif /* CAPTURE_H */
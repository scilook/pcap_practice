#ifndef CAPTURE_H
# define CAPTURE_H

#define LOCAL_IP		"LOCALHOST"
#define LOCAL_PORT		"5050"
#define SERVER_IP		"203.0.113.50"
#define SERVER_PORT		"80"

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

typedef struct s_list
{
	void *content;
	t_list *next;
} t_list;

typedef struct s_dev
{
	char *name;
	bpf_u_int32 net;
	bpf_u_int32 mask;
} t_dev;

typedef struct s_pcap_log
{
	int packets_cnt;
	int retrans_cnt;
	int size;
} t_pcap_log;

#endif /* CAPTURE_H */
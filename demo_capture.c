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

// Global handle for pcap session
pcap_t *g_handle;

// Log structure to hold session statistics
typedef struct s_pcap_log
{
	struct timeval first_ts;
	struct timeval last_ts;
	long long packets;
	long long bytes;
	// For simplified RTT: store SYN timestamp
	struct timeval syn_ts;
	double rtt; // in ms
	int syn_seen;
	int syn_ack_seen;
} t_pcap_log;

// Function to list and select network interfaces
char* find_best_device() {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs, *device;
	char *selected_dev = NULL;
	int i = 0;

	// Get list of all devices
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		printf("[ERROR] Error in pcap_findalldevs: %s\n", errbuf);
		return NULL;
	}

	printf("[INFO] Available network interfaces:\n");
	
	// Print all available devices
	for (device = alldevs; device != NULL; device = device->next) {
		printf("  %d. %s", ++i, device->name);
		if (device->description) {
			printf(" (%s)", device->description);
		}
		printf("\n");
		
		// Select first non-loopback interface or any interface if available
		if (selected_dev == NULL && 
		    strcmp(device->name, "lo") != 0 && 
		    strcmp(device->name, "any") != 0) {
			selected_dev = strdup(device->name);
		}
	}

	// If no specific interface found, try to use the first one
	if (selected_dev == NULL && alldevs != NULL) {
		selected_dev = strdup(alldevs->name);
	}

	pcap_freealldevs(alldevs);
	return selected_dev;
}

// Global log instance
t_pcap_log g_log;

// Initialize pcap session
int setup_pcap(const char *device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Create pcap handle
    g_handle = pcap_create(device, errbuf);
    if (g_handle == NULL) {
        printf("[ERROR] pcap_create failed: %s\n", errbuf);
        return -1;
    }
    
    // Set options
    pcap_set_snaplen(g_handle, BUFSIZ);
    pcap_set_promisc(g_handle, 1);
    pcap_set_timeout(g_handle, 1000);
    
    // Activate the handle
    int ret = pcap_activate(g_handle);
    if (ret != 0) {
        printf("[ERROR] pcap_activate failed: %s\n", pcap_statustostr(ret));
        pcap_close(g_handle);
        return -1;
    }
    
	// Apply more specific filter for common protocols
	struct bpf_program fp;
	// Filter for TCP traffic on common ports (HTTP, HTTPS, SSH, etc.)
	const char *filter = "tcp and (port 80 or port 443 or port 22 or port 21 or port 23 or port 25 or port 53 or port 3389)";
	if (pcap_compile(g_handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		printf("[ERROR] pcap_compile failed: %s\n", pcap_geterr(g_handle));
		pcap_close(g_handle);
		return -1;
	}    if (pcap_setfilter(g_handle, &fp) == -1) {
        printf("[ERROR] pcap_setfilter failed: %s\n", pcap_geterr(g_handle));
        pcap_freecode(&fp);
        pcap_close(g_handle);
        return -1;
    }
    
    pcap_freecode(&fp);
    return 0;
}

// Function to print summary
void print_summary() {
	double duration = (g_log.last_ts.tv_sec - g_log.first_ts.tv_sec) * 1000.0; // s to ms
	duration += (g_log.last_ts.tv_usec - g_log.first_ts.tv_usec) / 1000.0; // us to ms

	double throughput_kbps = 0;
	if (duration > 0) {
		throughput_kbps = (g_log.bytes * 8) / (duration / 1000.0) / 1000.0; // kbps
	}

	printf("\n=== TCP Session Analysis Report ===\n");
	printf("Total packets captured: %lld\n", g_log.packets);
	printf("Total bytes captured: %lld\n", g_log.bytes);
	printf("Session duration: %.2f ms\n", duration);
	printf("Average throughput: %.2f kbps\n", throughput_kbps);
	if (g_log.rtt > 0) {
		printf("Initial RTT (SYN->SYN/ACK): %.3f ms\n", g_log.rtt);
	} else {
		printf("Initial RTT: Not captured (handshake not observed)\n");
	}
	printf("=====================================\n");
}

// Signal handler for SIGINT
void signal_handler(int signum)
{
	printf("\n[SIGNAL] SIGINT received, stopping capture...\n");
	if (g_handle) {
		pcap_breakloop(g_handle);
	}
}

// pcap callback function
void pcap_callback(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet)
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

// Demo function to simulate TCP packets
void simulate_demo()
{
	printf("\n=== TCP Session Analysis Demo ===\n");
	printf("This demo simulates TCP packet capture and analysis.\n");
	printf("Key features demonstrated:\n");
	printf("1. Real-time packet parsing\n");
	printf("2. TCP session statistics\n");
	printf("3. RTT calculation\n");
	printf("4. Throughput measurement\n");
	printf("5. SIGINT signal handling\n");
	printf("\nPress Ctrl+C to stop and see the analysis report.\n");
	printf("==================================\n\n");

	// Simulate some TCP traffic for demo
	struct timeval current_time;
	gettimeofday(&current_time, NULL);
	
	// Initialize demo log
	memset(&g_log, 0, sizeof(t_pcap_log));
	g_log.first_ts = current_time;
	
	printf("[DEMO] Simulating TCP session...\n");
	printf("[INFO] Starting packet capture simulation\n");
	
	// Simulate packets being captured
	for (int i = 0; i < 10; i++) {
		g_log.packets++;
		g_log.bytes += (100 + (i * 50)); // Simulate varying payload sizes
		gettimeofday(&current_time, NULL);
		g_log.last_ts = current_time;
		
		printf("[PACKET %lld] TCP 192.168.1.100:%d -> 192.168.1.200:%d, Payload: %d bytes\n",
		       g_log.packets, 
		       8000 + i, 
		       80, 
		       100 + (i * 50));
		
		if (i == 0) {
			g_log.syn_seen = 1;
			g_log.syn_ts = current_time;
			printf("[RTT] SYN packet detected\n");
		} else if (i == 1) {
			g_log.syn_ack_seen = 1;
			double syn_time = g_log.syn_ts.tv_sec * 1000.0 + g_log.syn_ts.tv_usec / 1000.0;
			double syn_ack_time = current_time.tv_sec * 1000.0 + current_time.tv_usec / 1000.0;
			g_log.rtt = syn_ack_time - syn_time;
			printf("[RTT] SYN/ACK packet detected, RTT: %.3f ms\n", g_log.rtt);
		}
		
		usleep(100000); // 100ms delay between packets
	}
}

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev;

	printf("TCP Session Analysis Tool\n");
	printf("=========================\n");

	// Initialize pcap library
	if (pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf) != 0) {
		printf("[WARNING] pcap_init failed: %s\n", errbuf);
	}

	// Set up signal handler
	signal(SIGINT, signal_handler);

	// Find best network device
	dev = find_best_device();
	if (dev == NULL) {
		printf("[WARNING] No suitable network device found\n");
		printf("[INFO] Running in demo mode instead\n");
		simulate_demo();
		print_summary();
		return 0;
	}

	printf("[INFO] Selected device: %s\n", dev);

	// Setup pcap
	if (setup_pcap(dev) != 0) {
		printf("[WARNING] Failed to setup pcap on device %s\n", dev);
		printf("[INFO] Running in demo mode instead\n");
		simulate_demo();
		print_summary();
		return 0;
	}

	// Initialize log
	memset(&g_log, 0, sizeof(t_pcap_log));

	printf("[INFO] Starting TCP packet capture... Press Ctrl+C to stop.\n");

	// Start capture
	pcap_loop(g_handle, -1, pcap_callback, (u_char *)&g_log);

	// Print results
	if (g_log.packets > 0) {
		print_summary();
	} else {
		printf("\n[INFO] No packets were captured.\n");
	}

	// Cleanup
	if (dev) {
		free(dev);
	}
	pcap_close(g_handle);
	printf("[INFO] Capture finished.\n");

	return 0;
}

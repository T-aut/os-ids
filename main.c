#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/netfilter.h> // for NF_ACCEPT
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "cidr_trie.h"
#include <signal.h>
#include "suricata_interpreter.h"
#include <time.h>

volatile sig_atomic_t running = 1;
int total_packets_processed = 0;
FILE *performance_log;

static int packet_handler(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                          struct nfq_data *nfa, void *data)
{
    if (!running) return 0;

    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *payload;
    int payload_len;

    ph = nfq_get_msg_packet_hdr(nfa);

    payload_len = nfq_get_payload(nfa, &payload);
    if (payload_len >= 0)
    {
        struct iphdr *ip_header = (struct iphdr *)payload;
        if (ip_header->version == 4) {
            struct in_addr src_addr, dst_addr;
            src_addr.s_addr = ip_header->saddr;
            dst_addr.s_addr = ip_header->daddr;

            if (is_dangeorus_ip(inet_ntoa(src_addr))) {
                total_packets_processed++;
                return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_DROP, 0, NULL);
            }
        } 
    }

    packet_t packet;
    packet = payload_to_packet(payload, payload_len);
    process_packet(&packet);
    total_packets_processed++;

    return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
}

void start_performance_metrics() {
    performance_log = fopen("performance.csv", "w");
    if (!performance_log) {
        perror("Failed to open performance_log.csv");
        exit(1);
    }
    fprintf(performance_log, "packet_index,duration_micro\n");
}

void log_packet_time(int packet_index, double duration_micro) {
    fprintf(performance_log, "%d,%.2f\n", packet_index, duration_micro);
}

void end_performance_metrics() {
    fclose(performance_log);
}

struct nfq_handle *h;
struct nfq_q_handle *qh;

void handle_interrupt(int signal) {
    running = 0;
    printf("\nShutting down\n");

    printf("Total packets processed: %d\n", total_packets_processed);
    printf("Matched ip count: %d\n", get_matched_ip_count());
    printf("Matched suricata, but no content: %d\n", get_matched_but_no_content_count());
    printf("Matched suricata: %d\n", get_matched_count());

    system("sudo nft flush ruleset");
    nfq_destroy_queue(qh);
    nfq_close(h);
    cleanup();
    cleanup_suricata();
    end_performance_metrics();

    printf("Cleanup complete\n");
}

int main()
{
    signal(SIGINT, handle_interrupt);
    int fd;
    int rv;
    char buf[4096] __attribute__((aligned));

    init();
    init_suricata_rules();
    start_performance_metrics();

    system("sudo nft add table inet myfilter");
    // system("sudo nft add chain inet myfilter prerouting { type filter hook prerouting priority 0 \\; }");
    system("sudo nft add chain inet myfilter input  { type filter hook input priority 0 \\; }");

    // system("sudo nft add rule inet myfilter prerouting queue num 0");
    system("sudo nft add rule inet myfilter input queue num 0");
    
    // system("sudo nft add table ip myfilter");
    // system("sudo nft add chain ip myfilter prerouting { type filter hook prerouting priority -300 \\; }");
    // system("sudo nft add rule ip myfilter prerouting queue num 0");
    
    h = nfq_open();
    if (!h)
    {
        fprintf(stderr, "Error during nfq_open()\n");
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0)
    {
        fprintf(stderr, "Error during nfq_unbind_pf()\n");
        exit(1);
    }

    if (nfq_bind_pf(h, AF_INET) < 0)
    {
        fprintf(stderr, "Error during nfq_bind_pf()\n");
        exit(1);
    }

    qh = nfq_create_queue(h, 0, &packet_handler, NULL);
    if (!qh)
    {
        fprintf(stderr, "Error during nfq_create_queue()\n");
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        fprintf(stderr, "Can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && running)
    {
        if (rv < 0) perror("Received <0 bytes (recv error)\n");
        else {
            struct timespec start, end;
            clock_gettime(CLOCK_MONOTONIC, &start);

            nfq_handle_packet(h, buf, rv);

            clock_gettime(CLOCK_MONOTONIC, &end);
            double duration_us = (end.tv_sec - start.tv_sec) * 1e6 +
                                (end.tv_nsec - start.tv_nsec) / 1e3;

            log_packet_time(total_packets_processed, duration_us);
        }
    }

    return 0;
}

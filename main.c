#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/netfilter.h> // for NF_ACCEPT
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "cidr_trie.h"

static int packet_handler(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                          struct nfq_data *nfa, void *data)
{
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *payload;
    int payload_len;

    ph = nfq_get_msg_packet_hdr(nfa);
    // if (ph)
    // {
    //     // from network byte order to host byte order
    //     printf("Packet ID: %u\n", ntohl(ph->packet_id));
    // }

    payload_len = nfq_get_payload(nfa, &payload);
    if (payload_len >= 0)
    {
        struct iphdr *ip_header = (struct iphdr *)payload;
        if (ip_header->version == 4) {
            struct in_addr src_addr, dst_addr;
            src_addr.s_addr = ip_header->saddr;
            dst_addr.s_addr = ip_header->daddr;

            printf("IPv4 src: %s\n", inet_ntoa(src_addr));
            printf("IPv4 dst: %s\n", inet_ntoa(dst_addr));
            is_dangeorus_ip(inet_ntoa(src_addr));
        } else {
            printf("Non IPv4 packet\n");
        }

        // printf("Payload (%d bytes):\n", payload_len);
        // for (int i = 0; i < payload_len; ++i)
        // {
        //     printf("%02x ", payload[i]);
        //     if ((i + 1) % 16 == 0)
        //         printf("\n");
        // }
        printf("\n\n");
    }

    return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
}

int main()
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__((aligned));

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

    init();
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)
    {
        nfq_handle_packet(h, buf, rv);
    }
    cleanup();

    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}

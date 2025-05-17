#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/netfilter.h> // for NF_ACCEPT
#include <libnetfilter_queue/libnetfilter_queue.h>

// Callback function that processes each packet
static int packet_handler(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                          struct nfq_data *nfa, void *data)
{
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *payload;
    int payload_len;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph)
    {
        printf("Packet ID: %u\n", ntohl(ph->packet_id));
    }

    payload_len = nfq_get_payload(nfa, &payload);
    if (payload_len >= 0)
    {
        printf("Payload (%d bytes):\n", payload_len);
        for (int i = 0; i < payload_len; ++i)
        {
            printf("%02x ", payload[i]);
            if ((i + 1) % 16 == 0)
                printf("\n");
        }
        printf("\n\n");
    }

    // Accept the packet (let it go through)
    return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
}

int main()
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__((aligned));

    // Open library handle
    h = nfq_open();
    if (!h)
    {
        fprintf(stderr, "Error during nfq_open()\n");
        exit(1);
    }

    // Unbind existing nf_queue handler (if any)
    if (nfq_unbind_pf(h, AF_INET) < 0)
    {
        fprintf(stderr, "Error during nfq_unbind_pf()\n");
        exit(1);
    }

    // Bind this handler for AF_INET (IPv4)
    if (nfq_bind_pf(h, AF_INET) < 0)
    {
        fprintf(stderr, "Error during nfq_bind_pf()\n");
        exit(1);
    }

    // Create queue 0 and set callback
    qh = nfq_create_queue(h, 0, &packet_handler, NULL);
    if (!qh)
    {
        fprintf(stderr, "Error during nfq_create_queue()\n");
        exit(1);
    }

    // Set packet copy mode to copy entire packet
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        fprintf(stderr, "Can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    // Main loop to receive packets
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)
    {
        nfq_handle_packet(h, buf, rv);
    }

    // Clean up
    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}

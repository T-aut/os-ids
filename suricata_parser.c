#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define MAX_RULES 15000
#define MAX_CONTENTS 8
#define MAX_LINE 4096
#define HOME_NET "127.0.0.1"

typedef struct
{
    char action[16];
    char protocol[8];
    char src_ip[64];
    char src_port[16];
    char dst_ip[64];
    char dst_port[16];
    char direction[4];

    char *contents[MAX_CONTENTS];
    int content_lens[MAX_CONTENTS];
    int content_count;

    char msg[1024];
    char metadata[1024];
} rule_t;

rule_t rules[MAX_RULES];
int rule_count = 0;

char *str_trim(char *s)
{
    while (isspace((unsigned char)*s))
        s++;
    if (*s == 0)
        return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end))
        end--;
    end[1] = '\0';
    return s;
}


// Basic parser for rules
void parse_rule_line(char *line)
{
    if (rule_count >= MAX_RULES)
        return;
    if (line[0] == '#' || strstr(line, "flow:"))
        return;

    rule_t *r = &rules[rule_count];

    char *open_paren = strchr(line, '(');
    char *close_paren = strrchr(line, ')');
    if (!open_paren || !close_paren || open_paren > close_paren)
        return;

    size_t header_len = open_paren - line;
    char header_buf[256] = {0};
    strncpy(header_buf, line, header_len);
    char *header = str_trim(header_buf);
    sscanf(header, "%15s %7s %63s %15s %3s %63s %15s",
           r->action, r->protocol,
           r->src_ip, r->src_port,
           r->direction,
           r->dst_ip, r->dst_port);

    // Since we dont work with flows, interpret this as just ->
    if (strcmp(r->direction, "=>") == 0)
    {
        strcpy(r->direction, "->");
    }

    char body_buf[2048] = {0};
    size_t body_len = close_paren - open_paren - 1;
    strncpy(body_buf, open_paren + 1, body_len);

    char *token = strtok(body_buf, ";");
    while (token)
    {
        char *field = str_trim(token);
        if (strncmp(field, "content:", 8) == 0)
        {
            // Converts Suricata content string with |..| hex and ASCII to raw bytes
            if (r->content_count < MAX_CONTENTS)
            {
                char *start = strchr(field, '"');
                char *end = strrchr(field, '"');
                if (start && end && end > start)
                {
                    *end = '\0';
                    start++;

                    unsigned char *buf = malloc(256);
                    size_t out_len = 0;
                    char *p = start;
                    while (*p && out_len < 256)
                    {
                        if (*p == '|')
                        {
                            p++;
                            while (*p && *p != '|' && out_len < 256)
                            {
                                while (*p == ' ')
                                    p++;
                                if (!isxdigit(p[0]) || !isxdigit(p[1]))
                                    break;
                                char byte_str[3] = {p[0], p[1], '\0'};
                                buf[out_len++] = (unsigned char)strtol(byte_str, NULL, 16);
                                p += 2;
                                while (*p == ' ')
                                    p++;
                            }
                            if (*p == '|')
                                p++;
                        }
                        else
                        {
                            buf[out_len++] = (unsigned char)*p++;
                        }
                    }
                    r->contents[r->content_count] = malloc(out_len);
                    memcpy(r->contents[r->content_count], buf, out_len);
                    r->content_lens[r->content_count] = out_len;
                    r->content_count++;
                    free(buf);
                }
            }
        }
        else if (strncmp(field, "msg:", 4) == 0)
        {
            char *start = strchr(field, '"');
            char *end = strrchr(field, '"');
            if (start && end && end > start)
            {
                *end = '\0';
                strncpy(r->msg, start + 1, sizeof(r->msg));
            }
        }
        else if (strncmp(field, "metadata:", 9) == 0)
        {
            const char *start = field + 9;
            const char *semi = strchr(start, ';');
            size_t len = semi ? (size_t)(semi - start) : strlen(start);
            if (len >= sizeof(r->metadata))
                len = sizeof(r->metadata) - 1;
            strncpy(r->metadata, start, len);
            r->metadata[len] = '\0';
        }
        token = strtok(NULL, ";");
    }

    if (r->msg[0] == '\0')
    {
        printf("MSG NULL, LINE: %s\n", line);
        exit(1);
    }
    if (r->metadata[0] == '\0')
    {
        printf("METADATA NULL, LINE: %s\n", line);
        exit(1);
    }

    rule_count++;
}

// Match helper functions
bool str_ip_match(const char *rule_ip, const char *pkt_ip)
{
    if (strcmp(rule_ip, "$HOME_NET") == 0)
        return strcmp(pkt_ip, HOME_NET) == 0;
    if (strcmp(rule_ip, "$EXTERNAL_NET") == 0)
        return strcmp(pkt_ip, HOME_NET) != 0; // anything but home network
    return strcmp(rule_ip, "any") == 0 || strcmp(rule_ip, pkt_ip) == 0;
}

bool str_port_match(const char *rule_port, int pkt_port)
{
    if (strcmp(rule_port, "any") == 0)
        return true;

    int start = -1, end = -1;
    if (strchr(rule_port, ':'))
    {
        if (sscanf(rule_port, "%d:%d", &start, &end) == 2)
        {
            return pkt_port >= start && pkt_port <= end;
        }
        else if (sscanf(rule_port, ":%d", &end) == 1)
        {
            return pkt_port <= end;
        }
        else if (sscanf(rule_port, "%d:", &start) == 1)
        {
            return pkt_port >= start;
        }
    }
    else
    {
        int port = atoi(rule_port);
        return pkt_port == port;
    }
    return false;
}

bool protocol_match(const char *rule_proto, const char *pkt_proto)
{
    return strcmp(rule_proto, "any") == 0 || strcmp(rule_proto, pkt_proto) == 0;
}

typedef struct
{
    char protocol[8];
    char src_ip[64]; // we do not handle [a, b, c] notation, only single and ranges
    int src_port;
    char dst_ip[64];
    int dst_port;
    unsigned char *payload;
    int payload_len;
} packet_t;

bool match_payload(rule_t *r, const unsigned char *payload, int len)
{
    for (int i = 0; i < r->content_count; ++i)
    {
        if (memmem(payload, len, r->contents[i], r->content_lens[i]) == NULL)
            return false;
    }
    return true;
}

void process_packet(packet_t *pkt)
{
    for (int i = 0; i < rule_count; ++i)
    {
        rule_t *r = &rules[i];
        if (!protocol_match(r->protocol, pkt->protocol))
            continue;

        if (strcmp(r->direction, "->") == 0)
        {
            if (!str_ip_match(r->src_ip, pkt->src_ip))
                continue;
            if (!str_ip_match(r->dst_ip, pkt->dst_ip))
                continue;
            if (!str_port_match(r->src_port, pkt->src_port))
                continue;
            if (!str_port_match(r->dst_port, pkt->dst_port))
                continue;
        }
        else if (strcmp(r->direction, "<>") == 0)
        {
            bool direction1 = str_ip_match(r->src_ip, pkt->src_ip) && str_ip_match(r->dst_ip, pkt->dst_ip) &&
                              str_port_match(r->src_port, pkt->src_port) && str_port_match(r->dst_port, pkt->dst_port);
            bool direction2 = str_ip_match(r->src_ip, pkt->dst_ip) && str_ip_match(r->dst_ip, pkt->src_ip) &&
                              str_port_match(r->src_port, pkt->dst_port) && str_port_match(r->dst_port, pkt->src_port);
            if (!direction1 && !direction2)
                continue;
        }

        // TODO: payload match currently just dumps everything to bytes and does a check via memmem
        if (match_payload(r, pkt->payload, pkt->payload_len))
        {
            printf("[ALERT] %s\nMetadata: %s\n", r->msg, r->metadata);
        }
    }
}

void init_suricata_rules()
{
    system("[ -f /tmp/emerging-all.rules ] || wget -P /tmp/ https://rules.emergingthreats.net/open/suricata-7.0.3/emerging-all.rules");
    FILE *f = fopen("/tmp/emerging-all.rules", "r");
    if (!f)
    {
        perror("Could not read emerging-all.rules");
    }
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f))
    {
        parse_rule_line(line);
    }
    fclose(f);

    printf("[SURICATA_PARSER] Initialized %d rules\n", rule_count);
}

//udp, icmp, ftp, ssh, smtp
packet_t payload_to_packet(unsigned char *data, int len)
{
    packet_t pkt = {0};

    struct ip *iph = (struct ip *)data;
    strcpy(pkt.src_ip, inet_ntoa(iph->ip_src));
    strcpy(pkt.dst_ip, inet_ntoa(iph->ip_dst));

    int ip_hdr_len = iph->ip_hl * 4;
    unsigned char *transport = data + ip_hdr_len;

    switch (iph->ip_p)
    {
    case IPPROTO_UDP:
    {
        strcpy(pkt.protocol, "udp");
        struct udphdr *udph = (struct udphdr *)transport;
        pkt.src_port = ntohs(udph->uh_sport);
        pkt.dst_port = ntohs(udph->uh_dport);
        pkt.payload = transport + sizeof(struct udphdr);
        pkt.payload_len = len - ip_hdr_len - sizeof(struct udphdr);
        break;
    }
    case IPPROTO_ICMP:
    {
        strcpy(pkt.protocol, "icmp");
        pkt.src_port = 0;
        pkt.dst_port = 0;
        pkt.payload = transport + sizeof(struct icmphdr);
        pkt.payload_len = len - ip_hdr_len - sizeof(struct icmphdr);
        break;
    }
    default:
    {
        strcpy(pkt.protocol, "any");
        pkt.src_port = 0;
        pkt.dst_port = 0;
        pkt.payload = NULL;
        pkt.payload_len = 0;
    }
    }

    // Guess what protocol it could be (inaccurate)
    if (strcmp(pkt.protocol, "tcp") == 0)
    {
        if (pkt.dst_port == 21 || pkt.src_port == 21)
            strcpy(pkt.protocol, "ftp");
        else if (pkt.dst_port == 22 || pkt.src_port == 22)
            strcpy(pkt.protocol, "ssh");
        else if (pkt.dst_port == 25 || pkt.src_port == 25)
            strcpy(pkt.protocol, "smtp");
    }

    return pkt;
}

void cleanup_suricata() {
    for (int i = 0; i < rule_count; i++) {
        for (int j = 0; j < rules[i].content_count; j++) {
            free(rules[i].contents[j]);
            rules[i].contents[j] = NULL;
        }
    }
    rule_count = 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "emerging_threats_updater.h"

int matched_count = 0;

// Trie node structure
typedef struct TrieNode
{
    struct TrieNode *child[2]; // 0 or 1 bit
    int is_match;              // marks CIDR end
} TrieNode;

// Create a new TrieNode
TrieNode *create_node()
{
    TrieNode *node = calloc(1, sizeof(TrieNode));
    if (!node)
    {
        fprintf(stderr, "New node creation failed!\n");
        exit(1);
    }
    return node;
}

// Convert IPv4 address string to uint32_t
int ip_to_uint32(const char *ip_str, uint32_t *ip_out)
{
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1)
        return 0;
    *ip_out = ntohl(addr.s_addr);
    return 1;
}

// Parse CIDR like "1.10.16.0/20" into IP and prefix length
int parse_cidr(const char *cidr, uint32_t *ip, int *prefix_len)
{
    char ip_part[INET_ADDRSTRLEN];
    char *slash = strchr(cidr, '/');
    if (!slash)
        return 0;

    size_t ip_len = slash - cidr;
    if (ip_len >= sizeof(ip_part))
        return 0;
    strncpy(ip_part, cidr, ip_len);
    ip_part[ip_len] = '\0';

    *prefix_len = atoi(slash + 1);
    return ip_to_uint32(ip_part, ip);
}

// Insert a CIDR into the trie
void insert_cidr(TrieNode *root, uint32_t ip, int prefix_len)
{
    if (prefix_len < 0 || prefix_len > 32)
    {
        fprintf(stderr, "Invalid prefix length %d for CIDR %d\n", prefix_len, ip);
        return;
    }

    TrieNode *cur = root;
    for (int i = 31; i >= 32 - prefix_len; --i)
    {
        int bit = (ip >> i) & 1;
        if (!cur->child[bit])
            cur->child[bit] = create_node();
        cur = cur->child[bit];
    }
    cur->is_match = 1;
}

// Check if an IP matches any CIDR in the trie
int match_ip(TrieNode *root, uint32_t ip)
{
    if (!root)
        return 0;
    TrieNode *cur = root;

    for (int i = 31; i >= 0; --i)
    {
        if (!cur)
            return 0;
        int bit = (ip >> i) & 1;
        if (!cur->child[bit])
            return 0;
        cur = cur->child[bit];
        if (cur->is_match)
            return 1;
    }
    return 0;
}

void free_trie(TrieNode *node)
{
    if (!node)
        return;
    free_trie(node->child[0]);
    free_trie(node->child[1]);
    free(node);
}

TrieNode *root;

void init()
{
    int count = 0;
    int MAX_SIZE = 3000;
    root = create_node();
    char **cidrs = malloc(sizeof(char *) * MAX_SIZE);

    update_ip_set(cidrs, MAX_SIZE, &count);

    for (int i = 0; i < count; i++) {
        uint32_t ip;
        int prefix_len;
        if (parse_cidr(cidrs[i], &ip, &prefix_len)) {
            insert_cidr(root, ip, prefix_len);
        } else {
            fprintf(stderr, "Failed to parse CIDR: %s\n", cidrs[i]);
        }
        free(cidrs[i]); 
    }
    free(cidrs);

    printf("\n[IP_BLOCKLIST]: Initalized %d CIDR ranges\n", count);
}

void is_dangeorus_ip(char *input_ip)
{
    uint32_t ip;
    if (ip_to_uint32(input_ip, &ip))
    {
        if (match_ip(root, ip)) {
            printf("[ALERT] Potentially malicious IP matched: %s\n", input_ip);
            matched_count++;
        }
    }
    else
    {
        fprintf(stderr, "Invalid IP: %s\n", input_ip);
    }
}

int get_matched_ip_count()
{
    return matched_count;
}

void cleanup()
{
    free_trie(root);
}

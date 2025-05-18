#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "emerging_threats_updater.h"

// Trie node structure
typedef struct TrieNode {
    struct TrieNode *child[2]; // 0 or 1 bit
    int is_match;              // marks CIDR end
} TrieNode;

// Create a new TrieNode
TrieNode *create_node() {
    TrieNode *node = calloc(1, sizeof(TrieNode));
    return node;
}

// Convert IPv4 address string to uint32_t
int ip_to_uint32(const char *ip_str, uint32_t *ip_out) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) return 0;
    *ip_out = ntohl(addr.s_addr);
    return 1;
}

// Parse CIDR like "1.10.16.0/20" into IP and prefix length
int parse_cidr(const char *cidr, uint32_t *ip, int *prefix_len) {
    char ip_part[INET_ADDRSTRLEN];
    char *slash = strchr(cidr, '/');
    if (!slash) return 0;

    size_t ip_len = slash - cidr;
    if (ip_len >= sizeof(ip_part)) return 0;
    strncpy(ip_part, cidr, ip_len);
    ip_part[ip_len] = '\0';

    *prefix_len = atoi(slash + 1);
    return ip_to_uint32(ip_part, ip);
}

// Insert a CIDR into the trie
void insert_cidr(TrieNode *root, uint32_t ip, int prefix_len) {
    TrieNode *cur = root;
    for (int i = 31; i >= 32 - prefix_len; --i) {
        int bit = (ip >> i) & 1;
        if (!cur->child[bit])
            cur->child[bit] = create_node();
        cur = cur->child[bit];
    }
    cur->is_match = 1;
}

// Check if an IP matches any CIDR in the trie
int match_ip(TrieNode *root, uint32_t ip) {
    TrieNode *cur = root;
    for (int i = 31; i >= 0; --i) {
        int bit = (ip >> i) & 1;
        if (!cur->child[bit]) return 0;
        cur = cur->child[bit];
        if (cur->is_match) return 1;
    }
    return 0;
}

// Free the trie recursively
void free_trie(TrieNode *node) {
    if (!node) return;
    free_trie(node->child[0]);
    free_trie(node->child[1]);
    free(node);
}

TrieNode *root;

void init() {
    root = create_node();
    char **cidrs = malloc(sizeof(char *) * 5000);
    update_ip_set(cidrs, 5000);

    // for (int i = 0; i < 100; ++i) {
    //     printf("%s\n", cidrs[i]);
    // }

    // printf("%d\n", sizeof(cidrs));

    // TODO: fix max size, by making it dynamic (segfault)
    for (int i = 0; i < 1000; i++) {
        uint32_t ip;
        int prefix_len;
        if (parse_cidr(cidrs[i], &ip, &prefix_len)) {
            insert_cidr(root, ip, prefix_len);
            printf("Inserted: %s\n", cidrs[i]);
        } else {
            fprintf(stderr, "Failed to parse CIDR: %s\n", cidrs[i]);
        }
    }

    // Test IPs to match
    const char *test_ips[] = {
        "1.10.17.42",
        "10.123.5.6",
        "192.168.1.100",
        "8.8.8.8",
        "212.141.19.109",
        "212.141.19.110",
        "212.141.19.111",
        "109.172.92.205"
    };

    printf("\nTesting IPs:\n");
    for (int i = 0; i < sizeof(test_ips)/sizeof(test_ips[0]); i++) {
        uint32_t ip;
        if (ip_to_uint32(test_ips[i], &ip)) {
            printf("%s => %s\n", test_ips[i],
                   match_ip(root, ip) ? "Matched" : "Not Matched");
        } else {
            fprintf(stderr, "Invalid IP: %s\n", test_ips[i]);
        }
    }
    printf("\nInit complete\n");
}

void is_dangeorus_ip(char* input_ip) {
    uint32_t ip;
    if (ip_to_uint32(input_ip, &ip)) {
        printf("%s => %s\n", input_ip,
                match_ip(root, ip) ? "Matched" : "Not Matched");
    } else {
        fprintf(stderr, "Invalid IP: %s\n", input_ip);
    }
}

void cleanup() {
    free_trie(root);
}

typedef struct
{
    char protocol[8];
    char src_ip[64];
    int src_port;
    char dst_ip[64];
    int dst_port;
    unsigned char *payload;
    int payload_len;
} packet_t;

void init_suricata_rules();
void process_packet(packet_t *pkt);
int get_matched_count();
int get_matched_but_no_content_count();
void cleanup_suricata();
packet_t payload_to_packet(unsigned char *data, int len);
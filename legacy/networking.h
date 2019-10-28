#ifndef NETWORKING_H
#define NETWORKING_H

#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>

struct ip_tcp_hdr
{
    struct iphdr ip;
    struct tcphdr tcp;
};

struct pseudo_header
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
    struct tcphdr tcp;
};

void send_message_to_ip(const struct in_addr src, const struct in_addr dst, const unsigned short port, char *msg,
                        int msg_len);
void fill_iphdr(struct iphdr *hdr, const struct in_addr src, const struct in_addr dst);
void fill_tcphdr(struct tcphdr *hdr, const short src_port, const short dst_port);
void fill_tcp_checksum(struct ip_tcp_hdr *hdr);
unsigned short in_cksum(unsigned short *ptr, int nbytes);

#endif

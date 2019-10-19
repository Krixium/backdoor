#include "networking.h"

#include "packet_auth.h"

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <stdio.h> // remove

void send_message_to_ip(const struct in_addr address, unsigned short port, char *msg, int msg_len)
{
    const int SEND_FLAGS = 0;
    int sock;
    int hdr_len;
    int packet_len;
    struct sockaddr_in sin;
    struct ip_tcp_hdr send_tcp;
    char *packet;

    // open raw socket
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) return;

    // create ip header
    fill_iphdr(&send_tcp.ip, address);

    // create tcp header
    fill_tcphdr(&send_tcp.tcp, port, port); // change the dest port
    fill_tcp_checksum(&send_tcp);

    // create sockaddr
    sin.sin_family = AF_INET;
    sin.sin_port = send_tcp.tcp.source;
    sin.sin_addr.s_addr = send_tcp.ip.daddr;

    // create the entire packet
    hdr_len = send_tcp.ip.ihl * 5 + send_tcp.tcp.doff * 4;
    packet_len = hdr_len + msg_len;
    if ((packet = (char *)malloc(packet_len)))
    {
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

void fill_iphdr(struct iphdr* hdr, const struct in_addr address)
{
    hdr->ihl = 5;
    hdr->version = 4;
    hdr->tos = 0;
    hdr->tot_len = htons(40);
    hdr->id = (int)(255.0 * rand() / (RAND_MAX + 1.0));
    hdr->frag_off = 0;
    hdr->ttl = 64;
    hdr->protocol = IPPROTO_TCP;
    hdr->check = 0;
    hdr->saddr = address.s_addr; // change this to something else
    hdr->daddr = address.s_addr;
    hdr->check = in_cksum((unsigned short *)hdr, hdr->ihl * 5);
}

void fill_tcphdr(struct tcphdr* hdr, const short src_port, const short dst_port)
{
    hdr->source = htons(src_port);
    hdr->dest = htons(dst_port);
    hdr->seq = gen_auth_seq_num(src_port);

    hdr->ack_seq = 0;
    hdr->res1 = 0;
    hdr->doff = 5;
    hdr->fin = 0;
    hdr->syn = 1;
    hdr->rst = 0;
    hdr->psh = 0;
    hdr->ack = 0;
    hdr->urg = 0;
    hdr->res1 = 0;
    hdr->window = htons(512);
    hdr->check = 0;
    hdr->urg_ptr = 0;
}

void fill_tcp_checksum(struct ip_tcp_hdr* hdr)
{
    struct pseudo_header pHeader;

    pHeader.source_address = hdr->ip.saddr;
    pHeader.dest_address = hdr->ip.daddr;
    pHeader.placeholder = 0;
    pHeader.protocol = IPPROTO_TCP;
    pHeader.tcp_length = htons(hdr->tcp.doff * 4);
    memcpy((char *)&hdr->tcp, (char *)&pHeader.tcp, hdr->tcp.doff * 4);

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
unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
    register long sum;              /* assumes long == 32 bits */
    u_short oddbyte;
    register u_short answer;        /* assumes u_short == 16 bits */

    /*
    * Our algorithm is simple, using a 32-bit accumulator (sum),
    * we add sequential 16-bit words to it, and at the end, fold back
    * all the carry bits from the top 16 bits into the lower 16 bits.
    */

    sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nbytes == 1)
    {
        oddbyte = 0;                /* make sure top half is zero */
        *((u_char *) &oddbyte) = *(u_char *)ptr;   /* one byte only */
        sum += oddbyte;
    }

    /*
    * Add back carry outs from top 16 bits to low 16 bits.
    */

    sum  = (sum >> 16) + (sum & 0xffff);    /* add high-16 to low-16 */
    sum += (sum >> 16);             /* add carry */
    answer = ~sum;                  /* ones-complement, then truncate to 16 bits */
    return(answer);
} /* end in_cksm() */
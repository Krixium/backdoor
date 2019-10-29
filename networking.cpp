#include "networking.h"

#include <cstring>

#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

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
}

TcpStack::TcpStack(const struct in_addr &saddr, const struct in_addr &daddr, const short &sport,
                   const short &dport, const unsigned int &seqNum, const unsigned int &ackNum,
                   const unsigned char &tcpFlags, const UCharVector &payload) {
    // fill ip header
    this->ip.ihl = 5;
    this->ip.version = 4;
    this->ip.tos = 0;
    this->ip.id = (int)(244.0 * rand() / (RAND_MAX + 1.0));
    this->ip.frag_off = 0;
    this->ip.ttl = 64;
    this->ip.protocol = IPPROTO_TCP;
    this->ip.check = 0;
    this->ip.saddr = saddr.s_addr;
    this->ip.daddr = daddr.s_addr;
    this->ip.check = in_cksum((unsigned short *)&this->ip, this->ip.ihl * 4);

    // fill tcp header
    this->tcp.source = htons(sport);
    this->tcp.dest = htons(dport);
    this->tcp.seq = htonl(seqNum);
    this->tcp.ack_seq = htonl(ackNum);
    this->tcp.doff = 5;
    this->tcp.fin = tcpFlags & TcpStack::FIN_FLAG ? 1 : 0;
    this->tcp.syn = tcpFlags & TcpStack::SYN_FLAG ? 1 : 0;
    this->tcp.rst = tcpFlags & TcpStack::RST_FLAG ? 1 : 0;
    this->tcp.psh = tcpFlags & TcpStack::PSH_FLAG ? 1 : 0;
    this->tcp.ack = tcpFlags & TcpStack::ACK_FLAG ? 1 : 0;
    this->tcp.urg = tcpFlags & TcpStack::URG_FLAG ? 1 : 0;
    this->tcp.ece = tcpFlags & TcpStack::ECE_FLAG ? 1 : 0;
    this->tcp.cwr = tcpFlags & TcpStack::CWR_FLAG ? 1 : 0;
    this->tcp.res1 = 0;
    this->tcp.window = htons(512);
    this->tcp.check = 0;
    this->tcp.urg_ptr = 0;

    // calculate checksum
    this->calcChecksum();

    // fill total length in ip header
    this->ip.tot_len = htons(this->ip.ihl * 4 + this->tcp.doff * 4 + payload.size());

    // copy the payload
    for (int i = 0; i < payload.size(); i++) {
        this->payload.push_back(payload[i]);
    }
}

UCharVector TcpStack::getPacket() {
    const int ipLen = this->ip.ihl * 4;
    const int tcpLen = this->tcp.doff * 4;

    UCharVector packet;
    packet.resize(ntohs(this->ip.tot_len));

    memcpy(packet.data(), (char *)&this->ip, ipLen);
    memcpy(packet.data() + ipLen, (char *)&this->tcp, tcpLen);
    memcpy(packet.data() + ipLen + tcpLen, this->payload.data(), this->payload.size());

    return packet;
}

void TcpStack::calcChecksum() {
    struct TcpPseudoHeader pseudoHeader;

    pseudoHeader.srcAddr = this->ip.saddr;
    pseudoHeader.dstAddr = this->ip.daddr;
    pseudoHeader.placeholder = 0;
    pseudoHeader.protocol = IPPROTO_TCP;
    pseudoHeader.tcpLen = htons(this->tcp.doff * 4);
    memcpy((char *)&pseudoHeader.tcp, (char *)&this->tcp, this->tcp.doff * 4);

    this->tcp.check = in_cksum((unsigned short *)&pseudoHeader, sizeof(struct TcpPseudoHeader));
}

UdpStack::UdpStack(const struct in_addr &saddr, const struct in_addr &daddr, const short &sport,
                   const short &dport, const UCharVector &payload) {
    // fill the ip header
    this->ip.ihl = 5;
    this->ip.version = 4;
    this->ip.tos = 0;
    this->ip.id = (int)(244.0 * rand() / (RAND_MAX + 1.0));
    this->ip.frag_off = 0;
    this->ip.ttl = 64;
    this->ip.protocol = IPPROTO_UDP;
    this->ip.check = 0;
    this->ip.saddr = saddr.s_addr;
    this->ip.daddr = daddr.s_addr;
    this->ip.check = in_cksum((unsigned short *)&this->ip, this->ip.ihl * 4);

    // fill the udp header
    this->udp.source = htons(sport);
    this->udp.dest = htons(dport);
    this->udp.len = htons(8 + payload.size());

    // calculate checksum
    this->calcChecksum();

    // fill the total length in ip header
    this->ip.tot_len = htons(this->ip.ihl * 4 + this->udp.len + payload.size());

    // copy the payload
    for (int i = 0; i < payload.size(); i++) {
        this->payload.push_back(payload[i]);
    }
}

UCharVector UdpStack::getPacket() {
    const int ipLen = this->ip.ihl * 5;
    const int udpLen = ntohs(this->udp.len) - this->payload.size();

    UCharVector packet;
    packet.resize(ntohs(this->ip.tot_len));

    memcpy(packet.data(), (char *)&this->ip, ipLen);
    memcpy(packet.data() + ipLen, (char *)&this->udp, udpLen);
    memcpy(packet.data() + ipLen + udpLen, (char *)this->payload.data(), this->payload.size());

    return packet;
}

void UdpStack::calcChecksum() {
    struct UdpPseudoHeader pseudo_header;

    pseudo_header.srcAddr = this->ip.saddr;
    pseudo_header.dstAddr = this->ip.daddr;
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = IPPROTO_UDP;
    pseudo_header.udpLen = htons(this->udp.len);
    memcpy((char *)&pseudo_header.udp, (char *)&this->udp, this->udp.len);

    this->udp.check = in_cksum((unsigned short *)&pseudo_header, sizeof(struct UdpPseudoHeader));
}

NetworkEngine::NetworkEngine() { this->sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW); }

NetworkEngine::~NetworkEngine() {
    if (this->sd != -1) {
        close(this->sd);
    }
}

int NetworkEngine::sendTcp(const std::string &saddr, const std::string &daddr, const short &sport,
                           const short &dport, const unsigned char &tcpFlags,
                           const UCharVector &payload) {
    if (this->sd == -1) {
        return 0;
    }

    struct sockaddr_in sin;
    struct sockaddr_in sinSrc;
    struct sockaddr_in sinDst;

    if (inet_pton(AF_INET, saddr.c_str(), &sinSrc.sin_addr) != 1) {
        return 0;
    }

    if (inet_pton(AF_INET, daddr.c_str(), &sinDst.sin_addr) != 1) {
        return 0;
    }

    srand(time(NULL));
    unsigned int seq_num = rand() % 0xFFFFFFFF;
    unsigned int ack_num = rand() % 0xFFFFFFFF;

    TcpStack tcpStack(sinSrc.sin_addr, sinDst.sin_addr, sport, dport, seq_num, ack_num, tcpFlags,
                      payload);
    UCharVector packet = tcpStack.getPacket();

    if (packet.size() > NetworkEngine::MTU)
        return 0;

    sin.sin_family = AF_INET;
    sin.sin_port = tcpStack.tcp.source;
    sin.sin_addr.s_addr = tcpStack.ip.daddr;

    return sendto(this->sd, packet.data(), packet.size(), NetworkEngine::SEND_FLAGS,
                  (struct sockaddr *)&sin, sizeof(sin));
}

int NetworkEngine::sendUdp(const std::string &saddr, const std::string &daddr, const short &sport,
                           const short &dport, const UCharVector &payload) {
    if (this->sd == -1) {
        return 0;
    }

    struct sockaddr_in sin;
    struct sockaddr_in sinSrc;
    struct sockaddr_in sinDst;

    if (inet_pton(AF_INET, saddr.c_str(), &sinSrc.sin_addr) != 1) {
        return 0;
    }

    if (inet_pton(AF_INET, daddr.c_str(), &sinDst.sin_addr) != 1) {
        return 0;
    }

    UdpStack udpStack(sinSrc.sin_addr, sinDst.sin_addr, sport, dport, payload);
    UCharVector packet = udpStack.getPacket();

    if (packet.size() > NetworkEngine::MTU)
        return 0;

    sin.sin_family = AF_INET;
    sin.sin_port = udpStack.udp.source;
    sin.sin_addr.s_addr = udpStack.ip.daddr;

    return sendto(this->sd, packet.data(), packet.size(), NetworkEngine::SEND_FLAGS,
                  (struct sockaddr *)&sin, sizeof(sin));
}

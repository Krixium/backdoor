#ifndef NETWORKING_H
#define NETWORKING_H

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <string>
#include <vector>

using UCharVector = std::vector<unsigned char>;

struct TcpPseudoHeader {
    unsigned int srcAddr;
    unsigned int dstAddr;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcpLen;
    struct tcphdr tcp;
};

struct UdpPseudoHeader {
    unsigned int srcAddr;
    unsigned int dstAddr;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short udpLen;
    struct udphdr udp;
};

unsigned short in_cksum(unsigned short *ptr, int nbytes);

class TcpStack {
public:
    static const unsigned char FIN_FLAG = 0x01;
    static const unsigned char SYN_FLAG = 0x02;
    static const unsigned char RST_FLAG = 0x04;
    static const unsigned char PSH_FLAG = 0x08;
    static const unsigned char ACK_FLAG = 0x10;
    static const unsigned char URG_FLAG = 0x20;
    static const unsigned char ECE_FLAG = 0x40;
    static const unsigned char CWR_FLAG = 0x80;

    struct iphdr ip;
    struct tcphdr tcp;
    UCharVector payload;

public:
    TcpStack(const struct in_addr &saddr, const struct in_addr &daddr, const short &sport,
             const short &dport, const unsigned int &seqNum, const unsigned int &ackNum,
             const unsigned char &tcpFlags, const UCharVector &payload);

    UCharVector getPacket();

private:
    void calcChecksum();
};

class UdpStack {
public:
    struct iphdr ip;
    struct udphdr udp;
    UCharVector payload;

public:
    UdpStack(const struct in_addr &saddr, const struct in_addr &daddr, const short &sport,
             const short &dport, const UCharVector &payload);

    UCharVector getPacket();

private:
    void calcChecksum();
};

class NetworkEngine {
private:
    static const int SEND_FLAGS = 0;
    static const int MTU = 1500;

    int sd;

public:
    NetworkEngine();
    ~NetworkEngine();

    int sendTcp(const std::string &saddr, const std::string &daddr, const short &sport,
                const short &dport, const unsigned char &tcpFlags, const UCharVector &payload);

    int sendUdp(const std::string &saddr, const std::string &daddr, const short &sport,
                const short &dport, const UCharVector &payload);

private:
};

#endif

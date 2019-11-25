#ifndef NETWORK_ENGINE_H
#define NETWORK_ENGINE_H

#include <functional>
#include <string>
#include <thread>
#include <vector>

#include <pcap/pcap.h>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "KnockController.h"

using UCharVector = std::vector<unsigned char>;

class NetworkEngine {
private:
    static const int SEND_FLAGS;
    static const int MTU;

    struct sockaddr_in localAddress;

    int pcapPromiscuousMode;
    int pcapLoopDelay;

    int sd;
    int ifindex;
    unsigned char mac[ETH_ALEN];
    struct in_addr ip;

    pcap_t *session;

    std::thread *sniffThread;

    KnockController *knockController;

public:
    static const char *IP_FILTER;
    static const char *ARP_FILTER;

    std::vector<std::function<void(const struct pcap_pkthdr *, const unsigned char *, NetworkEngine *)>>
        LoopCallbacks;

public:
    NetworkEngine(const char *interfaceName);
    ~NetworkEngine();

    int sendRawTcp(const struct in_addr &saddr, const struct in_addr &daddr, const short &sport,
                   const short &dport, const unsigned char &tcpFlags, const UCharVector &payload);

    int sendRawUdp(const struct in_addr &saddr, const struct in_addr &daddr, const short &sport,
                   const short &dport, const UCharVector &payload);

    void startSniff(const char *filter);

    void stopSniff();

    inline const unsigned char *getMac() { return this->mac; }

    inline const struct in_addr *getIp() { return &(this->ip); }

    inline KnockController *getKnockController() { return this->knockController; }

    static void gotPacket(unsigned char *args, const struct pcap_pkthdr *header,
                          const unsigned char *packet);

private:
    void getInterfaceInfo(const char *interfaceName);
    void runSniff(const char *filter);
};

#endif

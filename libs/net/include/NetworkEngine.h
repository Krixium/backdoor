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

#include "Crypto.h"
#include "KnockController.h"
#include "TcpStack.h"
#include "UdpStack.h"
#include "authenticator.h"

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

    Crypto *crypto;

    KnockController *knockController;

public:
    std::vector<
        std::function<void(const struct pcap_pkthdr *, const unsigned char *, NetworkEngine *)>>
        LoopCallbacks;

public:
    NetworkEngine(const std::string &interfaceName, const std::string &key,
                  const std::string &pattern, const unsigned short port,
                  const unsigned int duration);
    ~NetworkEngine();

    int sendRawTcp(const struct in_addr &saddr, const struct in_addr &daddr, const short &sport,
                   const short &dport, const unsigned int seq, const unsigned int ack,
                   const unsigned char &tcpFlags, const UCharVector &payload);

    int sendRawUdp(const struct in_addr &saddr, const struct in_addr &daddr, const short &sport,
                   const short &dport, const UCharVector &payload);

    int sendCookedTcp(const struct in_addr &daddr, const unsigned short dport,
                      const UCharVector &data);

    int sendCoockedUdp(const struct in_addr &daddr, const unsigned short dport,
                       const UCharVector &data);

    int knockAndSend(const in_addr &daddr, const UCharVector &data);

    void startSyncSniff(const char *filter);

    void startAsyncSniff(const char *filter);

    void stopAsyncSniff();

    inline const unsigned char *getMac() { return this->mac; }

    inline const struct in_addr *getIp() { return &(this->ip); }

    inline Crypto *getCrypto() { return this->crypto; }

    inline KnockController *getKnockController() { return this->knockController; }

    inline bool isFromThisMachine(const ethhdr *eth) {
        for (int i = 0; i < ETH_ALEN; i++) {
            if (eth->h_source[i] != this->mac[i]) {
                return false;
            }
        }

        return true;
    }

    inline bool isIp(const ethhdr *eth) { return ntohs(eth->h_proto) == ETH_P_IP; }

    inline bool isTcp(const iphdr *ip) { return ip->protocol == IPPROTO_TCP; }

    inline bool isUdp(const iphdr *ip) { return ip->protocol == IPPROTO_UDP; }

    bool isAuth(const tcphdr *tcp);

    bool isAuth(const udphdr *udp);

    static void gotPacket(unsigned char *args, const struct pcap_pkthdr *header,
                          const unsigned char *packet);

private:
    void getInterfaceInfo(const char *interfaceName);
    void runSniff(const char *filter);
};

#endif

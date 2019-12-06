#include "NetworkEngine.h"

#include <cstring>
#include <iostream>

#include <linux/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "TcpStack.h"
#include "UdpStack.h"

// sendto flags
const int NetworkEngine::SEND_FLAGS = 0;
// maximum network transmission size
const int NetworkEngine::MTU = 1500;

/*
 * Constructor for NetworkEngine. The NetworkEngine handles all network aspects. This includes:
 *      - interface information
 *      - raw TCP/UDP sending
 *      - packet sniffing
 *      - port knocking
 *
 * Params:
 *      const std::string &intefaceName: The name of the interface to use.
 *
 *      const std::string &key: The crypto key.
 *
 *      const std::string &pattern: The port knocking pattern.
 *
 *      const unsigned short port: The port that will be opened after a successful port knock. Must
 *      be host byte order.
 *
 *      const unsigned int duration: The time in seconds for how long a port remains open after a
 *      successful port knock.
 */
NetworkEngine::NetworkEngine(const std::string &interfaceName, const std::string &key,
                             const std::string &pattern, const unsigned short port,
                             const unsigned int duration)
    : pcapPromiscuousMode(0), pcapLoopDelay(1), session(nullptr), sniffThread(nullptr) {
    this->sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    this->getInterfaceInfo(interfaceName.c_str());

    this->crypto = new Crypto(key);
    this->knockController = new KnockController(interfaceName, pattern, port, duration);
}

/*
 * Deconstructor for NetworkEngine.
 */
NetworkEngine::~NetworkEngine() {
    if (this->sd != -1) {
        close(this->sd);
    }

    this->stopAsyncSniff();

    delete this->crypto;
    delete this->knockController;
}

/*
 * Grabs the interface index number, MAC address, and IP address and saves it.
 *
 * Params:
 *      const char *interfaceName: The name of the interface to query.
 */
void NetworkEngine::getInterfaceInfo(const char *interfaceName) {
    struct ifreq ifr;
    int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

    if (sd <= 0) {
        close(sd);
        return;
    }

    if (strlen(interfaceName) > (IFNAMSIZ - 1)) {
        close(sd);
        return;
    }

    strcpy(ifr.ifr_name, interfaceName);

    // get interface index using name
    if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
        close(sd);
        return;
    }

    this->ifindex = ifr.ifr_ifindex;

    // get MAC address of the interface
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
        close(sd);
        return;
    }

    // copy mac address to output
    memcpy(this->mac, ifr.ifr_hwaddr.sa_data, 6);

    if (strlen(interfaceName) <= (IFNAMSIZ - 1)) {
        if (ioctl(sd, SIOCGIFADDR, &ifr) == -1) {
            close(sd);
            return;
        }

        if (ifr.ifr_addr.sa_family == AF_INET) {
            struct sockaddr_in *tmp = (struct sockaddr_in *)&ifr.ifr_addr;
            memcpy(&this->ip, &tmp->sin_addr, sizeof(struct sockaddr_in));
            this->ip.s_addr = ntohl(this->ip.s_addr);
        }
    }

    if (sd > 0) {
        close(sd);
    }
}

/*
 * Sends a TCP packet with the given parameters.
 *
 * Params:
 *      const struct in_addr &saddr: The source address.
 *
 *      const struct in_addr &daddr: The destination address.
 *
 *      const short &sport: The source port.
 *
 *      const short &dport: The destination port.
 *
 *      const unsigned int seq: The sequence number.
 *
 *      const unsigned int ack: The ack number.
 *
 *      const unsigned char &tcpFlags: The TCP flags to use.
 *
 *      const UCharVector &payload: The TCP payload.
 *
 * Returns:
 *      The number of bytes sent.
 */
int NetworkEngine::sendRawTcp(const struct in_addr &saddr, const struct in_addr &daddr,
                              const short &sport, const short &dport, const unsigned int seq,
                              const unsigned int ack, const unsigned char &tcpFlags,
                              const UCharVector &payload) {
    if (this->sd == -1) {
        return 0;
    }

    struct sockaddr_in sin;

    TcpStack tcpStack(saddr, daddr, sport, dport, seq, ack, tcpFlags, payload);
    UCharVector packet = tcpStack.getPacket();

    if (packet.size() > NetworkEngine::MTU) {
        return 0;
    }

    sin.sin_family = AF_INET;
    sin.sin_port = tcpStack.tcp.source;
    sin.sin_addr.s_addr = tcpStack.ip.daddr;

    return sendto(this->sd, packet.data(), packet.size(), NetworkEngine::SEND_FLAGS,
                  (struct sockaddr *)&sin, sizeof(sin));
}

/*
 * Sends a UDP packet with the given parameters.
 *
 * Params:
 *      const struct in_addr &saddr: The source address.
 *
 *      const struct in_addr &daddr: The destination address.
 *
 *      const short &sport: The source port.
 *
 *      const short &dport: The destination port.
 *
 *      const UCharVector &payload: The UDP payload.
 *
 * Returns:
 *      The number of bytes sent.
 */
int NetworkEngine::sendRawUdp(const struct in_addr &saddr, const struct in_addr &daddr,
                              const short &sport, const short &dport, const UCharVector &payload) {
    if (this->sd == -1) {
        return 0;
    }

    struct sockaddr_in sin;

    UdpStack udpStack(saddr, daddr, sport, dport, payload);
    UCharVector packet = udpStack.getPacket();

    if (packet.size() > NetworkEngine::MTU) {
        return 0;
    }

    sin.sin_family = AF_INET;
    sin.sin_port = udpStack.udp.source;
    sin.sin_addr.s_addr = udpStack.ip.daddr;

    return sendto(this->sd, packet.data(), packet.size(), NetworkEngine::SEND_FLAGS,
                  (struct sockaddr *)&sin, sizeof(sin));
}

/*
 * Sends data over TCP using the stack.
 *
 * Params:
 *      const struct in_addr &daddr: The destination to send the data to in host byte order.
 *
 *      const unsigned short dport: The port to use in host byte order.
 *
 *      const UCharVector &data: The data to send.
 *
 * Returns:
 *      The number of bytes written to the socket.
 */
int NetworkEngine::sendCookedTcp(const struct in_addr &daddr, const unsigned short dport,
                                 const UCharVector &data) {
    int result;
    int tcpSocket;
    struct sockaddr_in srvAddr;

    if ((tcpSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        return 0;
    }

    memset(&srvAddr, 0, sizeof(srvAddr));
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_port = htons(dport);
    srvAddr.sin_addr.s_addr = htonl(daddr.s_addr);

    if (connect(tcpSocket, (struct sockaddr *)&srvAddr, sizeof(srvAddr)) < 0) {
        return 0;
    }

    result = send(tcpSocket, data.data(), data.size(), 0);

    close(tcpSocket);

    return result;
}

/*
 * Sends data over UDP using the stack.
 *
 * Params:
 *      const struct in_addr &daddr: The destination to send the data to in host byte order.
 *
 *      const unsigned short dport: The port to use in host byte order.
 *
 *      const UCharVector &data: The data to send.
 *
 * Returns:
 *      The number of bytes written to the socket.
 */
int NetworkEngine::sendCoockedUdp(const struct in_addr &daddr, const unsigned short dport,
                                  const UCharVector &data) {
    int result;
    int udpSocket;
    struct sockaddr_in srvAddr;

    if ((udpSocket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return 0;
    }

    memset(&srvAddr, 0, sizeof(srvAddr));
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_port = htons(dport);
    srvAddr.sin_addr.s_addr = htonl(daddr.s_addr);

    result = sendto(udpSocket, data.data(), data.size(), 0, (struct sockaddr *)&srvAddr,
                    sizeof(srvAddr));

    close(udpSocket);

    return result;
}

/*
 * Performs the set sequence of port knocks and then sends data over a single TCP connection.
 *
 * Params:
 *      const in_addr &daddr: The destination in host byte order.
 *
 *      const UCharVector &data: The data to send once the knock is completed.
 *
 * Returns:
 *      The number of bytes written to the destination.
 */
int NetworkEngine::knockAndSend(const in_addr &daddr, const UCharVector &data) {
    UCharVector blank{0};

    // perform knock
    for (unsigned short port : this->knockController->getPattern()) {
        // use random source port
        this->sendRawUdp(this->ip, daddr, (Crypto::rand() % 55535) + 10000,
                         port, blank);
        sleep(1);
    }

    // do regular tcp connect and send
    return this->sendCookedTcp(daddr, this->knockController->getPort(), data);
}

void NetworkEngine::startSyncSniff(const char *filter) {
    this->runSniff(filter);
}

/*
 * Starts the PCAP sniffing thread.
 *
 * Params:
 *      const char *filter: The filter string.
 */
void NetworkEngine::startAsyncSniff(const char *filter) {
    this->sniffThread = new std::thread(&NetworkEngine::runSniff, this, filter);
}

/*
 * Stops the PCAP sniff loop.
 */
void NetworkEngine::stopAsyncSniff() {
    if (this->sniffThread != nullptr) {
        pcap_breakloop(this->session);
        if (this->sniffThread->joinable()) {
            this->sniffThread->join();
        }
        delete this->sniffThread;
        this->sniffThread = nullptr;
    }
}

/*
 * Checks a TCP header to see if it is authenticated using the authentication scheme.
 *
 * Params:
 *      const tcphdr *tcp: The TCP header to check.
 *
 * Returns:
 *      True if the header is authenticated, false otherwise.
 */
bool NetworkEngine::isAuth(const tcphdr *tcp) {
    return authenticator::isValidSignature(ntohs(tcp->source), ntohs(tcp->dest));
}

/*
 * Checks a UDP header to see if it is authenticated using the authentication scheme.
 *
 * Params:
 *      const udphdr *tcp: The UDP header to check.
 *
 * Returns:
 *      True if the header is authenticated, false otherwise.
 */
bool NetworkEngine::isAuth(const udphdr *udp) {
    return authenticator::isValidSignature(ntohs(udp->source), ntohs(udp->dest));
}

/*
 * The main entry point of the sniffing thread. Handles initialization of the pcap_loop.
 *
 * Params:
 *      const char *filter: The filter to use for the pcap_loop.
 */
void NetworkEngine::runSniff(const char *filter) {
    int i;

    pcap_if_t *allDevs;
    pcap_if_t *temp;

    struct bpf_program filterProgram;
    bpf_u_int32 netAddr = 0;

    char errBuff[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&allDevs, errBuff) == -1) {
        std::cerr << "pcap_findallDevs: " << errBuff << std::endl;
        return;
    }

    for (i = 0, temp = allDevs; temp; temp = temp->next, ++i) {
        if (!(temp->flags & PCAP_IF_LOOPBACK)) {
            for (pcap_addr_t *addr = temp->addresses; addr; addr = addr->next) {
                if (addr->addr->sa_family == AF_INET) {
                    memcpy(&this->localAddress, (char *)addr->addr, sizeof(struct sockaddr_in));
                }
            }
            break;
        }
    }

    this->session =
        pcap_open_live(temp->name, BUFSIZ, this->pcapPromiscuousMode, this->pcapLoopDelay, errBuff);
    if (!this->session) {
        std::cerr << "Could not open device: " << errBuff << std::endl;
        return;
    }

    if (pcap_compile(this->session, &filterProgram, filter, 0, netAddr)) {
        std::cerr << "Error calling pcap_compile" << std::endl;
        return;
    }

    if (pcap_setfilter(this->session, &filterProgram) == -1) {
        std::cerr << "Error setting filter" << std::endl;
        return;
    }

    pcap_loop(this->session, 0, &NetworkEngine::gotPacket, (unsigned char *)this);

    pcap_freealldevs(allDevs);
}

/*
 * The main pcap_loop callback function. Executes all callback functions stored in the network
 * engine given.
 *
 * Params:
 *      unsigned char *args: The user supplied arguments.
 *
 *      const struct pcap_pkthdr *header: The pcap packet header passed by the pcap_loop.
 *
 *      const unsigned char *packet: The network packet sniffed by pcap_loop.
 */
void NetworkEngine::gotPacket(unsigned char *args, const struct pcap_pkthdr *header,
                              const unsigned char *packet) {
    NetworkEngine *netEngine = (NetworkEngine *)args;

    struct ethhdr *eth = (struct ethhdr *)packet;
    struct iphdr *ip;
    struct udphdr *udp;

    // port knocking server side code
    if (netEngine->isIp(eth)) {
        ip = (struct iphdr *)(packet + ETH_HLEN);

        if (netEngine->isUdp(ip)) {
            udp = (struct udphdr *)(packet + ETH_HLEN + (ip->ihl * 4));

            unsigned short port = ntohs(udp->dest);
            struct in_addr address;
            address.s_addr = ip->saddr;
            netEngine->getKnockController()->process(&address, port);
        }
    }

    for (int i = 0; i < netEngine->LoopCallbacks.size(); i++) {
        (netEngine->LoopCallbacks[i])(header, packet, netEngine);
    }
}

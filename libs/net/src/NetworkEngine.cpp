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
 *      const std::string &pattern: The port knocking pattern.
 *
 *      const unsigned short port: The port that will be opened after a successful port knock. Must
 *      be host byte order.
 *
 *      const unsigned int dutation: The time in seconds for how long a port remains open after a
 *      successful port knock.
 */
NetworkEngine::NetworkEngine(const std::string &interfaceName, const std::string &pattern,
                             const unsigned short port, const unsigned int duration)
    : pcapPromiscuousMode(0), pcapLoopDelay(1), session(nullptr), sniffThread(nullptr) {
    this->sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    this->getInterfaceInfo(interfaceName.c_str());

    this->knockController = new KnockController(interfaceName, pattern, port, duration);
}

/*
 * Deconstructor for NetworkEngine.
 */
NetworkEngine::~NetworkEngine() {
    if (this->sd != -1) {
        close(this->sd);
    }

    this->stopSniff();

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
 *      const unsigned char &tcpFlags: The TCP flags to use.
 *
 *      const UCharVector &payload: The TCP payload.
 *
 * Returns:
 *      The number of bytes sent.
 */
int NetworkEngine::sendRawTcp(const struct in_addr &saddr, const struct in_addr &daddr,
                              const short &sport, const short &dport, const unsigned char &tcpFlags,
                              const UCharVector &payload) {
    if (this->sd == -1) {
        return 0;
    }

    struct sockaddr_in sin;

    srand(time(NULL));
    unsigned int seq_num = rand() % 0xFFFFFFFF;
    unsigned int ack_num = rand() % 0xFFFFFFFF;

    TcpStack tcpStack(saddr, daddr, sport, dport, seq_num, ack_num, tcpFlags, payload);
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
 * Starts the PCAP sniffing thread.
 *
 * Params:
 *      const char *filter: The filter string.
 */
void NetworkEngine::startSniff(const char *filter) {
    this->sniffThread = new std::thread(&NetworkEngine::runSniff, this, filter);
}

/*
 * Stops the PCAP sniff loop.
 */
void NetworkEngine::stopSniff() {
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
    for (int i = 0; i < netEngine->LoopCallbacks.size(); i++) {
        (netEngine->LoopCallbacks[i])(header, packet, netEngine);
    }
}

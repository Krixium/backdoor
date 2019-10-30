#include <iostream>
#include <string>
#include <vector>

#include <unistd.h>

#include "crypto.h"
#include "networking.h"

int main(int argc, char *argv[]) {
    const std::string srcAddr = "192.168.75.75";
    const std::string dstAddr = "123.123.123.123";
    const short sport = 42069;
    const short dport = 7575;

    Crypto cryptoEngine("key");
    UCharVector data({'a', 'b', 'c', 'd', 'e'});

    // crypto examples
    UCharVector ciphertext = cryptoEngine.enc(data);
    UCharVector plaintext = cryptoEngine.dec(ciphertext);

    NetworkEngine netEngine;

    // tcp sending examples
    for (int i = 0; i < 10; i++) {
        std::cout << netEngine.sendTcp(srcAddr, dstAddr, sport, dport, TcpStack::SYN_FLAG, data)
                  << std::endl;
        std::cout << netEngine.sendTcp(srcAddr, dstAddr, sport, dport,
                                       TcpStack::SYN_FLAG | TcpStack::ACK_FLAG, data)
                  << std::endl;
    }

    // udp sending examples
    for (int i = 0; i < 10; i++) {
        std::cout << netEngine.sendUdp(srcAddr, dstAddr, sport, dport, data) << std::endl;
    }

    // adding functions to process payload received from pcap loop
    auto cb1 = [](const unsigned char *payload) -> void { std::cout << "cb1" << std::endl; };
    auto cb2 = [](const unsigned char *payload) -> void { std::cout << "cb2" << std::endl; };
    auto cb3 = [](const unsigned char *payload) -> void { std::cout << "cb3" << std::endl; };
    netEngine.packetHandlerFunctions.push_back(cb1);
    netEngine.packetHandlerFunctions.push_back(cb2);
    netEngine.packetHandlerFunctions.push_back(cb3);

    // exmaple of starting and stopping sniffing
    std::cout << "starting sniff" << std::endl;
    netEngine.startSniff();
    sleep(2);
    std::cout << "stopping sniff" << std::endl;
    netEngine.stopSniff();

    return 0;
}

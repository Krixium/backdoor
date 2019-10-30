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

    UCharVector ciphertext = cryptoEngine.enc(data);
    UCharVector plaintext = cryptoEngine.dec(ciphertext);

    NetworkEngine netEngine;
    std::cout << "Sending "
              << netEngine.sendTcp(srcAddr, dstAddr, sport, dport, TcpStack::SYN_FLAG, data)
              << " bytes on TCP" << std::endl;
    std::cout << "Sending "
              << netEngine.sendTcp(srcAddr, dstAddr, sport, dport,
                                   TcpStack::SYN_FLAG | TcpStack::ACK_FLAG, data)
              << " bytes on TCP" << std::endl;
    // udp send causes malloc corrupted top size
    // std::cout << "Sending " << netEngine.sendUdp(srcAddr, dstAddr, sport, dport, data)
    //           << " bytes on UDP" << std::endl;



    netEngine.packetHandlerFunctions.push_back([](const unsigned char *payload) -> void {
        std::cout << std::hex << payload[0] << std::endl;
    });

    netEngine.packetHandlerFunctions.push_back([](const unsigned char *payload) -> void {
        std::cout << std::hex << payload[1] << std::endl;
    });

    netEngine.packetHandlerFunctions.push_back([](const unsigned char *payload) -> void {
        std::cout << std::hex << payload[2] << std::endl;
    });

    std::cout << "starting sniff" << std::endl;
    netEngine.startSniff();
    sleep(2);
    std::cout << "stopping sniff" << std::endl;
    netEngine.stopSniff();

    return 0;
}

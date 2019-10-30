#include <iostream>
#include <string>
#include <vector>

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
    std::cout << "Sending " << netEngine.sendUdp(srcAddr, dstAddr, sport, dport, data)
              << " bytes on UDP" << std::endl;

    return 0;
}

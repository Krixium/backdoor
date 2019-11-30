#ifndef REMOTE_CODE_EXECUTER_H
#define REMOTE_CODE_EXECUTER_H

#include "NetworkEngine.h"

#include <string>

namespace RemoteCodeExecuter {
const char *CMD_START_STR;
const char *CMD_STOP_STR;
const char *DATA_START_STR;
const char *DATA_STOP_STR;

int sendCommand(NetworkEngine *net, const struct in_addr daddr, const std::string &cmd);

void netCallback(const pcap_pkthdr *header, const unsigned char *packet, NetworkEngine *net);

char *getCommand(char *payload);

char *getResponse(char *payload);

void executeCommand(NetworkEngine *net, const unsigned int daddr, const char *cmd);
}; // namespace RemoteCodeExecuter

#endif

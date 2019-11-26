#include <memory>
#include <string>
#include <unordered_map>

#include <arpa/inet.h>

#include "KnockState.h"

class KnockController {
private:
    std::string interface;
    std::string pattern;
    std::string portString;
    std::string duration;
    std::unordered_map<unsigned int, KnockState*> states;

public:
    KnockController(const std::string &interfaceName, const std::string &pattern, const unsigned short port, const unsigned int duration);
    ~KnockController();

    void process(const struct in_addr* address, const unsigned port);

private:
    void openPortForIp(const struct in_addr* address);
};

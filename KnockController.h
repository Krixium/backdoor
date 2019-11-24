#include <memory>
#include <string>
#include <unordered_map>

#include <arpa/inet.h>

#include "KnockState.h"

class KnockController {
private:
    std::string pattern;
    std::string interface;
    std::string portString;
    std::string duration;
    std::unordered_map<unsigned int, std::unique_ptr<KnockState>> states;

public:
    KnockController(const std::string& pattern, const std::string& interface,
                    const unsigned port, const unsigned int duration);

    void process(const struct in_addr* address, const unsigned port);

private:
    void openPortForIp(const struct in_addr* address, const unsigned port);
};

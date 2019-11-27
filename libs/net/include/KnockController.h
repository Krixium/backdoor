#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <arpa/inet.h>

#include "KnockState.h"

class KnockController {
private:
    std::string interface;
    std::string portString;
    std::string duration;
    std::vector<unsigned short> pattern;
    std::unordered_map<unsigned int, KnockState*> states;

public:
    KnockController(const std::string &interfaceName, const std::string &pattern, const unsigned short port, const unsigned int duration);
    ~KnockController();

    void process(const struct in_addr* address, const unsigned port);

    inline const std::vector<unsigned short> &getPattern() { return this->pattern; };

    inline const unsigned short getPort() { return std::stoi(this->portString); }

    static int parsePattern(const std::string &pattern, std::vector<unsigned short> *out);

private:
    void openPortForIp(const struct in_addr* address);
};

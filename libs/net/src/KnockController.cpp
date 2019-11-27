#include "KnockController.h"

#include <iostream>
#include <sstream>
#include <thread>

/*
 * The constructor for the KnockController. The KnockController is responsible for handling all the
 * knock sequence states of all the hosts and is responsible for opening the firewall when the
 * correct packet sequence is supplied by a host.
 *
 * Params:
 *      const std::string &interfaceName: The interface that will receive packets after the firewall
 *      has been opened.
 *
 *      const std::string &pattern: The knock sequence pattern. This should be a comma separated
 *      list of port numbers with no spaces. E.g. "8001,8002,8003,8004"
 *
 *      const unsigned short port: The port that will be opened after successful port knocking.
 *
 *      const unsigned int duration: The time in seconds for how long the port should remain open
 *      after knocking.
 */
KnockController::KnockController(const std::string &interfaceName, const std::string &pattern,
                                 const unsigned short port, const unsigned int duration)
    : interface(interface), portString(std::to_string(port)), duration(std::to_string(duration)),
      states() {
    KnockController::parsePattern(pattern, &this->pattern);
}

/*
 * The deconstructor for the KnockController. Cleans up memory.
 */
KnockController::~KnockController() {
    for (auto &it : this->states) {
        delete it.second;
    }
}

/*
 * Processes the knock sequence packet sent by a given host. The port will be used in a attempt to
 * increment the state of the knock sequence associated with that host. If the knock sequence
 * reaches the open state, a firewall rule will open the port for that host and the state will be
 * reset.
 *
 * Params:
 *      const struct in_addr *address: The address of the sending host with the address in network
 *      byte order.
 *
 *      const unsigned port: The port to use to increment the knock state. This should be from the
 *      remote host and should be in host byte order.
 */
void KnockController::process(const struct in_addr *address, const unsigned port) {
    unsigned int key = (unsigned int)address->s_addr;

    try {
        this->states.at(key)->tick(port);
    } catch (const std::out_of_range &orr) {
        this->states.insert({key, new KnockState(this->pattern)});
        this->states.at(key)->tick(port);
    }

    if (this->states.at(key)->isOpen()) {
        this->openPortForIp(address);
        this->states.at(key)->reset();
    }
}

/*
 * Creates a set of iptable rules to open up the port for the given address for a set duration.
 *
 * Params:
 *      const struct in_addr *address: The address to open up the firewall for. Must be network byte
 * order.
 */
void KnockController::openPortForIp(const struct in_addr *address) {
    std::string dottedDecimalString(inet_ntoa(*address));
    std::string command("iptables -i " + this->interface + " -A INPUT -s " + dottedDecimalString +
                        " -p tcp --dport " + this->portString + " -j ACCEPT; sleep " +
                        this->duration + "; iptables -i " + this->interface + " -D INPUT -s " +
                        dottedDecimalString + " -p tcp --dport " + this->portString + " -j ACCEPT");

    std::thread t([](const std::string &c) { system(c.c_str()); }, command);
    t.detach();
}

int KnockController::parsePattern(const std::string &pattern, std::vector<unsigned short> *out) {
    int i = 0;
    std::istringstream iss(pattern);

    out->clear();
    for (std::string tmp; std::getline(iss, tmp, ',');) {
        try {
            unsigned short num = std::stoi(tmp);
            out->push_back(num);
            i++;
        } catch (const std::invalid_argument &ia) {
            std::cerr << "Invalid argument in KnockState constructor: " << ia.what() << std::endl;
        }
    }

    return i;
}

#include "KnockController.h"

#include <iostream>
#include <thread>

KnockController::KnockController(const std::string &pattern, const std::string &interface,
                                 const unsigned port, const unsigned int duration)
    : pattern(pattern), interface(interface), portString(std::to_string(port)),
      duration(std::to_string(duration)), states() {}

KnockController::~KnockController() {
    for (auto &it : this->states) {
        delete it.second;
    }
}

void KnockController::process(const struct in_addr *address, const unsigned port) {
    unsigned int key = (unsigned int)address->s_addr;

    std::cout << "ticking, " << key << ", " << port << std::endl;

    try {
        this->states.at(key)->tick(port);
    } catch (const std::out_of_range &orr) {
        this->states.insert({key, new KnockState(this->pattern)});
        this->states.at(key)->tick(port);
    }

    if (this->states.at(key)->isOpen()) {
        std::cout << "opening port" << std::endl;
        this->openPortForIp(address, port);
        this->states.at(key)->reset();
    }
}

void KnockController::openPortForIp(const struct in_addr *address, const unsigned port) {
    std::string dottedDecimalString(inet_ntoa(*address));
    std::string openCommand("iptables -i " + this->interface + " -A INPUT -s " +
                            dottedDecimalString + " -p tcp --dport " + this->portString +
                            " -j ACCEPT; ");
    std::string closeCommand("iptables -i " + this->interface + " -D INPUT -s " +
                             dottedDecimalString + " -p tcp --dport " + this->portString +
                             " -j ACCEPT; ");
    std::string sleepCommand("sleep " + this->duration + "; ");
    std::string finalCommand(openCommand + sleepCommand + finalCommand);

    std::cout << "executing command: " << finalCommand << std::endl;
    std::thread t([](const std::string &c) { system(c.c_str()); }, finalCommand);
    t.detach();
}

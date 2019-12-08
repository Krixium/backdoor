#ifndef FILE_MONITOR_H
#define FILE_MONITOR_H

#include <sys/inotify.h>

#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "NetworkEngine.h"

class FileMonitor;

using EventCallback = std::function<void(FileMonitor *, struct inotify_event *)>;

class FileMonitor {
private:
    std::thread *t;
    std::mutex lock;
    bool running;

    int inotifyFd;
    std::unordered_map<std::string, int> wds;
    std::unordered_map<int, std::vector<unsigned int>> destinations;
    EventCallback createdCallback;
    EventCallback modifiedCallback;
    EventCallback deletedCallback;

public:
    FileMonitor(EventCallback &created, EventCallback &modified, EventCallback &deleted);

    ~FileMonitor();

    inline const std::vector<unsigned int> &getDestinations(const int wd) {
        return this->destinations.at(wd);
    };

    inline void setCreatedCallback(EventCallback &cb) { this->createdCallback = std::move(cb); }

    inline void setModifiedCallback(EventCallback &cb) { this->modifiedCallback = std::move(cb); }

    inline void setDeletedCallback(EventCallback &cb) { this->deletedCallback = std::move(cb); }

    int addWatchFile(const std::string &path);

    inline void startMonitoring() {
        this->stopMonitoring();
        this->t = new std::thread(&FileMonitor::runMonitoring, this);
    }

    inline void stopMonitoring() {
        std::lock_guard<std::mutex> guard(this->lock);
        if (!this->running) {
            return;
        }
        this->running = false;

        if (this->t == nullptr) {
            return;
        }

        if (this->t->joinable()) {
            this->t->join();
        }

        delete this->t;
    }

    void netCallback(const pcap_pkthdr *header, const unsigned char *packet, NetworkEngine *net);

    static void sendRequest(const std::string &file, const in_addr daddr, NetworkEngine *net);

private:
    void runMonitoring();
};

#endif

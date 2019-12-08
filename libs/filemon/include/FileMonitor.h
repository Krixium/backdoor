#ifndef FILE_MONITOR_H
#define FILE_MONITOR_H

#include <sys/inotify.h>

#include <functional>
#include <mutex>
#include <set>
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

    std::unordered_map<int, std::set<unsigned int>> destinations;
    std::unordered_map<int, std::string> wdToPathLookup;
    std::unordered_map<unsigned int, std::vector<std::pair<int, std::string>>> hostToFileLookup;

    EventCallback createdCallback;
    EventCallback modifiedCallback;
    EventCallback deletedCallback;

public:
    FileMonitor(EventCallback &created, EventCallback &modified, EventCallback &deleted);

    ~FileMonitor();

    inline const std::set<unsigned int> &getDestinations(const int wd) {
        return this->destinations.at(wd);
    };

    inline const std::vector<std::string> getFullPathsForHost(const unsigned int host, const struct inotify_event *e) {
        auto pairs = this->hostToFileLookup.at(host);
        std::vector<std::string> results;

        for (auto p : pairs) {
            if (p.first == e->wd && p.second == std::string(e->name)) {
                results.push_back(this->wdToPathLookup.at(p.first) + p.second);
            }
        }

        return results;
    }

    inline void setCreatedCallback(EventCallback &cb) { this->createdCallback = cb; }

    inline void setModifiedCallback(EventCallback &cb) { this->modifiedCallback = cb; }

    inline void setDeletedCallback(EventCallback &cb) { this->deletedCallback = cb; }

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

    static std::pair<std::string, std::string> splitPath(std::string &fullPath);

private:
    void runMonitoring();
};

#endif

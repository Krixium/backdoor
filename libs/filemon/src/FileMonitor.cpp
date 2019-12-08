#include "FileMonitor.h"

#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

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

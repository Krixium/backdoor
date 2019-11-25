#ifndef KEYLOGGER_H
#define KEYLOGGER_H

#include <fcntl.h>
#include <linux/input.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

class Keylogger {
public:
    Keylogger(std::string log_filename);

    void start_logging();
    bool stop_logging();

private:
    void process_keys();
    std::string get_keyboard_path();

    std::string m_keyboard_path;
    std::string m_log_filename;
    int m_keyboard_fd;
    FILE* m_fptr;
    struct input_event m_ev;

    bool m_done; // make atomic?
};

#endif
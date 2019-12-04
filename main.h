#ifndef MAIN_H
#define MAIN_H

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

using Properties = std::unordered_map<std::string, std::string>;

void printUsage(const char *name);

Properties getConfig(const std::string& filename);

inline std::vector<std::string> tokenizeString(std::string s) {
    std::vector<std::string> output;
    std::istringstream ss(s);

    do {
        std::string tmp;
        ss >> tmp;
        output.push_back(tmp);
    } while (ss);

    return output;
}

int clientMode(const Properties &p);

int serverMode(const Properties &p);

#endif

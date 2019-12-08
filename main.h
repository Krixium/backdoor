#ifndef MAIN_H
#define MAIN_H

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

using Properties = std::unordered_map<std::string, std::string>;
using UCharVector = std::vector<unsigned char>;

void printUsage(const char *name);

Properties getConfig(const std::string &filename);

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

inline UCharVector fileToBuffer(std::string &filename) {
    UCharVector buffer;
    std::string line;
    std::ifstream infile;

    infile.open(filename);
    while (!infile.eof()) {
        std::getline(infile, line);
        buffer.insert(buffer.end(), line.begin(), line.end());
    }
    infile.close();

    return buffer;
}

int clientMode(const Properties &p, char *programName);

int serverMode(const Properties &p);

int maskProcess(char *original, const char *mask);

#endif

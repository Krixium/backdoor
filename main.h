#ifndef MAIN_H
#define MAIN_H

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>

using Properties = std::unordered_map<std::string, std::string>;

void printUsage(const char *name);

Properties getConfig(const std::string& filename);

int clientMode(const Properties &p);

int serverMode(const Properties &p);

#endif

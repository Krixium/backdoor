#ifndef MAIN_H
#define MAIN_H

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>

using Properties = std::unordered_map<std::string, std::string>;

Properties getConfig(const std::string& filename);

#endif

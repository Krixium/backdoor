#include "KnockState.h"

#include <iostream>
#include <sstream>
#include <string>

KnockState::KnockState(const std::string& pattern) : currentIndex(0) {
    std::istringstream iss(pattern);

    for (std::string tmp; std::getline(iss, tmp, ','); ) {
        try {
            unsigned short num = std::stoi(tmp);
            std::cout << num << std::endl;
            this->state.push_back(num);
        } catch (const std::invalid_argument& ia) {
            std::cerr << "Invalid argument in KnockState constructor: " << ia.what() << std::endl;
        }
    }
}

void KnockState::tick(const unsigned short port) {
    if (this->state[currentIndex] == port) {
        currentIndex++;
    }
}

bool KnockState::isOpen() {
    return currentIndex == this->state.size();
}

void KnockState::reset() {
    this->currentIndex = 0;
}


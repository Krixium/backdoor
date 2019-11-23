#ifndef KNOCK_STATE_H
#define KNOCK_STATE_H

#include <string>
#include <vector>

class KnockState {
    private:
        unsigned int currentIndex;
        std::vector<unsigned short> state;

    public:
        KnockState(const std::string& pattern);

        void tick(const unsigned short port);
        bool isOpen();
        void reset();

};

#endif

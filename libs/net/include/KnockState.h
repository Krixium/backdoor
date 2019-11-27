#ifndef KNOCK_STATE_H
#define KNOCK_STATE_H

#include <vector>

class KnockState {
    private:
        unsigned int currentIndex;
        std::vector<unsigned short> pattern;

    public:
        KnockState(const std::vector<unsigned short>& pattern);

        void tick(const unsigned short port);
        bool isOpen();
        void reset();

};

#endif

#include "KnockState.h"

/*
 * The constructor for the KnockState. The KnockState keeps track of what part of the knock sequence
 * any host is currently on.
 *
 * Params:
 *      const std::vector<unsigned short>& pattern: The port sequence that will be used as the knock pattern.
 */
KnockState::KnockState(const std::vector<unsigned short>& pattern) : currentIndex(0), pattern(pattern) {}

/*
 * Attempts to increment the state or "tick" the state of the knock sequence. The internal state of
 * the object will progress if the supplied port is the next port in the sequence.
 *
 * Params:
 *      const unsigned short port: The port from the incoming packet.
 */
void KnockState::tick(const unsigned short port) {
    if (this->pattern[currentIndex] == port) {
        currentIndex++;
    }
}

/*
 * Checks if the state is open. A state is considered open if it has reached the end of the sequence
 * and closed if it hasn't.
 *
 * Returns:
 *      True if the state is open, false if the state is closed.
 */
bool KnockState::isOpen() { return currentIndex == this->pattern.size(); }

/*
 * Resets the state back to the default state or starting state.
 */
void KnockState::reset() { this->currentIndex = 0; }

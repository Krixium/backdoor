#ifndef AUTHENTICATOR_H
#define AUTHENTICATOR_H

#include <openssl/sha.h>

namespace authenticator {
unsigned short generateSignature(const unsigned short value);
bool isValidSignature(const unsigned short n, const unsigned short m);
} // namespace authenticator

#endif

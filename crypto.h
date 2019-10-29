#ifndef CRYPTO_H
#define CRYPTO_H

#include <vector>

using UCharVector = std::vector<unsigned char>;

class Crypto {
public:
    UCharVector key;

public:
    Crypto(const UCharVector &key);

    UCharVector enc(const UCharVector &data);
    UCharVector dec(const UCharVector &data);
};

#endif

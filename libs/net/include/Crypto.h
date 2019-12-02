#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <vector>

using UCharVector = std::vector<unsigned char>;

class Crypto {
private:
    UCharVector key;

public:
    Crypto(const UCharVector &key);
    Crypto(const std::string &key);

    UCharVector enc(const UCharVector &data);
    UCharVector dec(const UCharVector &data);

    static unsigned int rand();
};

#endif

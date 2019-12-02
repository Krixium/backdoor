#include "Crypto.h"

#include <stdlib.h>
#include <time.h>

#include <openssl/rand.h>

Crypto::Crypto(const UCharVector &key) {
    srand(time(NULL));

    this->key.resize(key.size());

    for (unsigned long i = 0; i < key.size(); i++) {
        this->key[i] = key[i];
    }
}

Crypto::Crypto(const std::string &key) {
    this->key.resize(key.size());

    for (unsigned long i = 0; i < key.size(); i++) {
        this->key[i] = key[i];
    }
}

UCharVector Crypto::enc(const UCharVector &data) {
    UCharVector result(data.size());

    for (unsigned long i = 0; i < data.size(); i++) {
        result[i] = data[i] ^ this->key[i % this->key.size()];
    }

    return result;
}

UCharVector Crypto::dec(const UCharVector &data) {
    UCharVector result(data.size());

    for (unsigned long i = 0; i < data.size(); i++) {
        result[i] = data[i] ^ this->key[i % this->key.size()];
    }

    return result;
}

unsigned int Crypto::rand() {
    unsigned int buf;
    if (RAND_bytes((unsigned char *)&buf, sizeof(unsigned int)) == 1) {
        return buf;
    } else {
        return rand();
    }
}

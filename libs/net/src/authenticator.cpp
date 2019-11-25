#include "authenticator.h"

#include <string>

unsigned short Authenticator::generateSignature(const unsigned short value) {
    SHA256_CTX ctx;
    std::string valueString;
    unsigned char hashBuffer[32];
    unsigned short result = 0;
    char *resultPointer = (char *)&result;

    valueString = std::to_string(value);
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, valueString.c_str(), valueString.length());
    SHA256_Final(hashBuffer, &ctx);

    for (int i = 0, j = sizeof(unsigned short) - 1; i < sizeof(unsigned short); i++, j--) {
        resultPointer[i] = hashBuffer[j];
    }

    return result;
}

bool Authenticator::isValidSignature(const unsigned short n, const unsigned short m) {
    return m == this->generateSignature(n);
}

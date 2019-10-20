#ifndef CRYPTO_H
#define CRYPTO_H

void xor_bytes(const char *key, const int key_len, const char *input,
               char *output, const int input_len);

#endif
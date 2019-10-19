#ifndef CRYPTO_H
#define CRYPTO_H

void xor_string(const char *key, const int key_len, const char* input, char *output, const int input_len);
void hex_str_to_bytes(const char *hex_str, char *output, const int len);

#endif
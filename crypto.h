#ifndef CRYPTO_H
#define CRYPTO_H

void xor_encrypt(const char *key, const int key_len, const char* plaintext, const int plaintext_len, char *ciphertext);
void xor_decrypt(const char *key, const int key_len, const char* ciphertext, const int ciphertext_len, char *plaintext);

#endif
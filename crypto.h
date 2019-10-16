#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/rsa.h>

RSA *init_public_rsa_with_key(const unsigned char *key);
RSA *init_public_rsa_with_file(const char *filename);
RSA *init_private_rsa_with_key(const unsigned char *key);
RSA *init_private_rsa_with_file(const char *filename);

int rsa_encrypt_with_public(const unsigned char *plaintext, const int plaintext_len, const unsigned char *key, unsigned char *ciphertext);
int rsa_decrypt_with_private(const unsigned char *ciphertext, const int ciphertext_len, const unsigned char *key, unsigned char *plaintext);
int rsa_encrypt_with_private(const unsigned char *plaintext, const int plaintext_len, const unsigned char *key, unsigned char *ciphertext);
int rsa_decrypt_with_public(const unsigned char *ciphertext, const int ciphertext_len, const unsigned char *key, unsigned char *plaintext);

#endif
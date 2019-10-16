#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/rsa.h>

RSA *init_public_rsa_with_key(const unsigned char *key);
RSA *init_public_rsa_with_file(const char *filename);
RSA *init_private_rsa_with_key(const unsigned char *key);
RSA *init_private_rsa_with_file(const char *filename);

int rsa_encrypt_with_public(const unsigned char *data, const int data_len, const unsigned char *key, unsigned char *output);
int rsa_decrypt_with_private(const unsigned char *enc_data, const int enc_data_len, const unsigned char *key, unsigned char *output);

int rsa_encrypt_with_private(const unsigned char *data, const int data_len, const unsigned char *key, unsigned char *output);
int rsa_decrypt_with_public(const unsigned char *enc_data, const int enc_data_len, const unsigned char *key, unsigned char *output);

#endif
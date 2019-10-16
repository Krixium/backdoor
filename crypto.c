#include "crypto.h"

#include <openssl/bio.h>
#include <openssl/pem.h>

static const int DEFAULT_PADDING_MODE = RSA_PKCS1_PADDING;

RSA *create_public_rsa_key(const unsigned char *key)
{
    RSA *rsa = NULL;
    BIO *keybio = BIO_new_mem_buf(key, -1);

    if (keybio == NULL)
    {
        return 0;
    }

    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    return rsa;
}

RSA *create_private_rsa_key(const unsigned char *key)
{
    RSA *rsa = NULL;
    BIO *keybio = BIO_new_mem_buf(key, -1);

    if (keybio == NULL)
    {
        return 0;
    }

    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    return rsa;
}

int rsa_encrypt_with_public(const unsigned char *data, const int data_len, const unsigned char *key, unsigned char *output)
{
    RSA *rsa = create_public_rsa_key(key);
    return RSA_public_encrypt(data_len, data, output, rsa, DEFAULT_PADDING_MODE);
}

int rsa_decrypt_with_private(const unsigned char *enc_data, const int enc_data_len, const unsigned char *key, unsigned char *output)
{
    RSA *rsa = create_private_rsa_key(key);
    return RSA_private_decrypt(enc_data_len, enc_data, output, rsa, DEFAULT_PADDING_MODE);
}

int rsa_encrypt_with_private(const unsigned char *data, const int data_len, const unsigned char *key, unsigned char *output)
{
    RSA *rsa = create_private_rsa_key(key);
    return RSA_private_encrypt(data_len, data, output, rsa, DEFAULT_PADDING_MODE);
}

int rsa_decrypt_with_public(const unsigned char *enc_data, const int enc_data_len, const unsigned char *key, unsigned char *output)
{
    RSA *rsa = create_public_rsa_key(key);
    return RSA_public_decrypt(enc_data_len, enc_data, output, rsa, DEFAULT_PADDING_MODE);
}this is 
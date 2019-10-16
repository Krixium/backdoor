#include "crypto.h"

#include <openssl/bio.h>
#include <openssl/pem.h>

static const int DEFAULT_PADDING_MODE = RSA_PKCS1_PADDING;

/*
* Creates a RSA key structure from the given public key in PEM format.
*
* Params:
*       const unsigned char *key: The public key in PEM format.
*
* Returns:
*       THe RSA key structure created from the public key PEM.
*/
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

/*
* Creates a RSA key structure from the given public key in PEM format.
*
* Params:
*       const unsigned char *key: The private key in PEM format.
*
* Returns:
*       THe RSA key structure created from the private key PEM.
*/
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

/*
* Encrypts data with the RSA public key.
*
* Params:
*       const unsigned char *plaintext: Pointer to the block of plaintext.
*       const int plaintext_len: Length of the plaintext.
*       const unsigned char *key: Pointer to the public key in PEM format.
*       unsigned char *ciphertext: A pointer to a buffer to hold ciphertext.
*
* Returns:
*       The length of the ciphertext.
*/
int rsa_encrypt_with_public(const unsigned char *plaintext, const int plaintext_len, const unsigned char *key, unsigned char *ciphertext)
{
    RSA *rsa = create_public_rsa_key(key);
    return RSA_public_encrypt(plaintext_len, plaintext, ciphertext, rsa, DEFAULT_PADDING_MODE);
}

/*
* Decrypts data with the RSA private key.
*
* Params:
*       const unsigned char *ciphertext: Pointer to the block of ciphertext.
*       const int ciphertext_len: Length of the ciphertext.
*       const unsigned char *key: Pointer to the private key in PEM format.
*       unsigned char *plaintext: A pointer to a buffer to hold the plaintext.
*
* Returns:
*       The length of the plaintext.
*/
int rsa_decrypt_with_private(const unsigned char *ciphertext, const int ciphertext_len, const unsigned char *key, unsigned char *plaintext)
{
    RSA *rsa = create_private_rsa_key(key);
    return RSA_private_decrypt(ciphertext_len, ciphertext, plaintext, rsa, DEFAULT_PADDING_MODE);
}

/*
* Encrypts data with the RSA private key.
*
* Params:
*       const unsigned char *plaintext: Pointer to the block of plaintext.
*       const int plaintext_len: Length of the plaintext.
*       const unsigned char *key: Pointer to the private key in PEM format.
*       unsigned char *ciphertext: A pointer to a buffer to hold ciphertext.
*
* Returns:
*       The length of the ciphertext.
*/
int rsa_encrypt_with_private(const unsigned char *plaintext, const int plaintext_len, const unsigned char *key, unsigned char *ciphertext)
{
    RSA *rsa = create_private_rsa_key(key);
    return RSA_private_encrypt(plaintext_len, plaintext, ciphertext, rsa, DEFAULT_PADDING_MODE);
}

/*
* Decrypts data with the RSA public key.
*
* Params:
*       const unsigned char *ciphertext: Pointer to the block of ciphertext.
*       const int ciphertext_len: Length of the ciphertext.
*       const unsigned char *key: Pointer to the public key in PEM format.
*       unsigned char *plaintext: A pointer to a buffer to hold the plaintext.
*
* Returns:
*       The length of the plaintext.
*/
int rsa_decrypt_with_public(const unsigned char *ciphertext, const int ciphertext_len, const unsigned char *key, unsigned char *plaintext)
{
    RSA *rsa = create_public_rsa_key(key);
    return RSA_public_decrypt(ciphertext_len, ciphertext, plaintext, rsa, DEFAULT_PADDING_MODE);
}
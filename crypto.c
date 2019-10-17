#include "crypto.h"

/*
 * Performs XOR encryption.
 *
 * Params:
 *      const char *key: The key to use for encryption.
 *      const int key_len: The length of key.
 *      const char *plaintext: The plaintext to encrypt.
 *      const int plaintext_len: The length of plaintext.
 *      char *ciphertext: A pointer to the output buffer. Must be the same size as plaintext.
 *
 * Returns:
 *      1 if the encryption was successful, 0 otherwise.
 */
void xor_encrypt(const char *key, const int key_len, const char* plaintext, const int plaintext_len, char *ciphertext)
{
    for (int i = 0; i < plaintext_len; i++)
    {
        ciphertext[i] = plaintext[i] ^ key[i % key_len];
    }
}

/*
 * Performs xor decryption.
 *
 * Params:
 *      const char *key: The key to use for encryption.
 *      const int key_len: The length of key.
 *      const char *ciphertext: The ciphertext to decrypt.
 *      const int ciphertext_len: The length of the ciphertext.
 *      char *plaintext: A pointer to the output buffer. Must be the same size as ciphertext.
 *
 * Returns:
 *      1 if the decryption was successful, 0 otherwise.
 */
void xor_decrypt(const char *key, const int key_len, const char* ciphertext, const int ciphertext_len, char *plaintext)
{
    for (int i = 0; i < ciphertext_len; i++)
    {
        plaintext[i] = ciphertext[i] ^ key[i % key_len];
    }
}

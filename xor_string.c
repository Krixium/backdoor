#include <stdio.h>
#include <string.h>
#include "crypto.h"


int main(int argc, char** argv)
{
    char buffer[1024];
    memset(buffer, 0, 1024);

    xor_string(argv[1], strlen(argv[1]), argv[2], buffer, strlen(argv[2]));

    for (int i = 0; i < strlen(argv[2]); i++)
    {
        printf("%02x", buffer[i]);
    }

    return 0;
}
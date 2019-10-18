#include <stdio.h>
#include <string.h>
#include "crypto.h"


int main(int argc, char** argv)
{
    char buffer[1024];
    xor_encrypt(argv[1], strlen(argv[1]), argv[2], strlen(argv[2]), buffer);
    printf("%s", buffer);
    return 0;
}
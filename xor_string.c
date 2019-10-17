#include <stdio.h>
#include <string.h>
#include "crypto.h"


int main(int argc, char** argv) 
{
    int i, x, y;
    if (!argv[1] || !argv[2]) {
        printf("%s <key> <string>\n", argv[0]);
        return 1;
    }
    x = strlen(argv[1]);
    y = strlen(argv[2]);
    for (i = 0; i < y; ++i) {
        argv[2][i] ^= argv[1][(i % x)];
    }
    printf("%s", argv[1]);
    return 0;
}
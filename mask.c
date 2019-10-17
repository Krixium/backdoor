#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <errno.h>
#include <stdio.h>

#include "mask.h"

int mask_process(char* original, const char* mask)
{
    const int MAX_PROCESS_LEN = 16;
    strncpy(original, mask, MAX_PROCESS_LEN);
    original[MAX_PROCESS_LEN] = 0;
    if (prctl(PR_SET_NAME, mask, 0, 0) == -1)
    {
        perror("prctl");
        return -1;
    }
    return 0;
}

int raise_privileges(uid_t uid) {
    if (setuid(uid) == -1) {
        perror("setuid");
        return -1;
    }
    if (setgid(uid) == -1) {
        perror("setgid");
        return -1;
    }
    return 0;
}
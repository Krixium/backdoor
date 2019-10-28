#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>

#include "mask.h"

/*
 * Changes the name of the process to the mask.
 *
 * Params:
 *      char *original: Argv[0]
 *
 *      const char *mask: The new name use.
 *
 * Returns:
 *      0 if the process name was masked, -1 otherwise.
 */
int mask_process(char *original, const char *mask)
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

/*
 * Changes the privileges of the application to the privileges of the given user.
 *
 * Params:
 *      uid_t uid: The ID of the user to use.
 */
int raise_privileges(uid_t uid)
{
    if (setuid(uid) == -1)
    {
        perror("setuid");
        return -1;
    }
    if (setgid(uid) == -1)
    {
        perror("setgid");
        return -1;
    }
    return 0;
}
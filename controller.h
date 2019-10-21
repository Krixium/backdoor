#ifndef CONTROLLER_H
#define CONTROLLER_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/ip.h>

void issue_command(const struct in_addr this_ip, const char *address, const char *command);

#endif

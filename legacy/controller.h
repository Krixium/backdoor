#ifndef CONTROLLER_H
#define CONTROLLER_H

#include <linux/ip.h>
#include <netinet/in.h>
#include <sys/socket.h>

void issue_command(const struct in_addr this_ip, const char *address, const char *command);

#endif

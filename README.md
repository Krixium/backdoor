# Backdoor

## Configuration
    Add key value pairs that are seperated by '=' into the backdoor.conf file.

    Required Fields:
        interface: The name of the network interface.
        key: The encryption key.

        knockPattern: The port pattern to use for port knocking. This is a comma seperated list with no spaces.
        knockPort: The port to open after a successful port knock.
        knockDuration: The duration that the knockPort should remain open.

        keylogLootFile: The file to stop keystrokes retrieved by the keylogger.

## Usage
    ./backdoor [client|server|test]
        client - client mode a.k.a victim mode
        server - server mode a.k.a command center mode
        test - testing mode
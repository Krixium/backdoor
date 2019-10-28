# backdoor
Backdoor program for Linux.

## How to compile

### Instructions for Fedora
```
dnf install -y libpcap* openssl* cmake
git clone https://github.com/Krixium/backdoor
cd backdoor
mkdir build
cd build
cmake ..
make
```

## Usage
Server mode: Run ```backdoor server``` to start the backdoor server.

Client mode: Run ```backdoor client <ip of server> <command>``` to send a command to the backdoor server at the given IP address.

## Documentation and Testing
State diagram, pseudocode, testing documents, and packet captures can be found in the `docs` folder.


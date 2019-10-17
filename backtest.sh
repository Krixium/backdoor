#!/bin/bash

xor_string()
{
    echo $((16#$(echo -n $1 | sha256sum | cut -c1-8)))
}

KEY=
SOURCE_PORT=7575
SEQ_NUM=$(xor_string $SOURCE_PORT)

COM_START="start["
COM_END="]end"

OPTS="-c 1 -M $SEQ_NUM -s $SOURCE_PORT "

if [ -z  "$1" ]; then
    echo "$0 <ip> <command>"
    exit 0
fi
if [ -z "$2" ]; then
    echo "$0 <ip> <command>"
    exit 0
fi

echo "Sending $COM_START$2$COM_END to hping3 $OPTS $1"

echo $(xor_string $COM_START$2$COM_END) | hping3 $OPTS $1




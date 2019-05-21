"""
 Helper functions for Dev Course Networks Series
"""

import socket
import struct
import subprocess
from binascii import hexlify,unhexlify

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
    # next header fields for all cept tcp, udp, icmp and a couple of other ones...
    lst_hdrs = ["\x00", "\x2b", "\x2c", "\x2e", "\x32", "\x33", "\x3b", "\x3c"]
    
    class err(Exception):
        def __str__(self):
            return "Something went wrong. Check your packet or step through with pdb"

    def checksum(data):
        #if len(data) % 2:
        #    raise err
        sum = 0
        for i in range(0, len(data)/2):
            sum += struct.unpack(">H", data[i*2:(i+1)*2])[0]
        sum = (((sum >> 16) + sum) & 0xffff) ^ 0xffff
        return sum

    try:
        type = struct.unpack(">H", frame[12:14])[0]
    except:
        raise err
    if type != 0x0800 and type != 0x86dd:
        raise Exception("I don't know how to checksum non-IP ethertype 0x%04x" % type)

    try:
        ippkt = frame[14:]
        ipclass = struct.unpack(">H", ippkt[0:2])[0] & 0x0ff0
        iplabel = struct.unpack(">L", ippkt[0:4])[0] & 0x0fffff
        ippayload = struct.unpack(">H", ippkt[4:6])[0]
        if ippayload == 0:
            # calculate payload:
            ippayload = len(ippkt[40:])
            ippkt = ippkt[:4] + struct.pack(">H", ippayload) + ippkt[6:]
        ipnexthdr = (ord(ippkt[6]))
        iphoplim = (ord(ippkt[7]))

        # Upper-Layer Packet Length is 32-bit in pseudo header vice 16 bit in IPv6 header
        # If upper layer protocol includes length field, use that, if not, take payload length from ipv6 header, minus length of any extension headers

    except:
        raise err

    if ipnexthdr == 58:
        try:
            # Calculate payload without extension headers:
            ip_pseudohdr = ippkt[8:24] + ippkt[24:40] + "\x00\x00" + str(struct.pack(">H", ippayload)) + "\x00\x00\x00" + ippkt[6]
            icmpsum = checksum(ip_pseudohdr+ippkt[40:])
            ippkt = ippkt[:40+2] + struct.pack(">H", icmpsum) + ippkt[40+4:]
        except:
            raise err
    elif ipnexthdr == 17:
        # UDP
        try:
            udp_payload = struct.unpack(">H", ippkt[40+4:40+6])
            ip_pseudohdr = ippkt[8:24] + ippkt[24:40] + "\x00\x00" + str(struct.pack(">H", udp_payload[0])) + "\x00\x00\x00" + ippkt[6]
            sum = checksum(ip_pseudohdr + ippkt[40:])
            sumoff = 40 + {6:16, 17:6}[ipnexthdr]
            udp_len = len(ippkt[40:])-1
            ippkt = ippkt[:sumoff] + struct.pack(">H", sum) + ippkt[sumoff+2:]
            # length auto-calc:
            ippkt = ippkt[:44] + struct.pack(">H", udp_len) + ippkt[46:]
        except:
            raise err
    elif ipnexthdr == 6:
        # TCP
        try:
            ip_pseudohdr = ippkt[8:24] + ippkt[24:40] + "\x00\x00" + str(struct.pack(">H", ippayload)) + "\x00\x00\x00" + ippkt[6]
            sum = checksum(ip_pseudohdr + ippkt[40:])
            sumoff = 40 + {6:16, 17:6}[ipnexthdr]
            ippkt = ippkt[:sumoff] + struct.pack(">H", sum) + ippkt[sumoff+2:]
        except:
            raise err
    else:
        raise Exception("I don't know how to checksum IP proto 0x%02x" % ipnexthdr)

    rawsend(frame[:14] + ippkt, dev)


import os

if os.geteuid() != 0:
    print """
WARNING:
You are not root, you probably should be.
      ...especially if this is somebody else's box ;-)
"""




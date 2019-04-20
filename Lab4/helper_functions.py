import binascii
import socket
import uuid


def get_my_mac():
    mac_str = hex(uuid.getnode())[2:-1]
    corrected = '0'*(12-len(mac_str)) + mac_str
    return binascii.unhexlify(corrected)
    
    
def mac_str_to_hex(addr):
    """expects address of the format 00:11:22:33:44:55"""
    return binascii.unhexlify(addr.replace(':', ''))
    
    
def ipv4_str_to_bytes(addr):
    """expects address of format '172.16.0.37'"""
    return ''.join(map(chr, map(int, addr.split('.'))))
    
    
def ipv6_str_to_bin(addr):
    return socket.inet_pton(socket.AF_INET6, addr)
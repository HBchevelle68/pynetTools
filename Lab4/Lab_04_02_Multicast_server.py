import socket
import struct

###########################################################
#
#   Lab 4 Task 2 - Multicast Server
#
#       Server that can receive UDP datagrams on
#       Multicast address
#
###########################################################

# Configure address info for connection
dst_ip = "FF02::111:4"
dst_port = 1337

# Create and configure UDP socket (DGRAM)
my_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
my_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

group_bin = socket.inet_pton(socket.AF_INET6, dst_ip)
group = group_bin + struct.pack('@I', 0)
my_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, group)

# Bind it to the port
my_sock.bind(('', dst_port))

# Loop, printing any data we receive
while True:
	data, sender = my_sock.recvfrom(1500)
    	while data[-1:] == '\0': 
		data = data[:-1]
    	print (str(sender) + '  ' + repr(data))

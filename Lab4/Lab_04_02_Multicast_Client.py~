import socket
import time

###########################################################
#
#   Lab 4 Task 2 - Multicast Client
#
#       Client that can send UDP datagrams on
#       Multicast address
#
###########################################################

# Configure address info for connection
dst_ip = "FF02::666:666:666"
dst_port = 7777
# Create and configure UDP socket (DGRAM)
my_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
#my_sock.connect((dst_ip, dst_port))

num = 0
while 1:
	data = ("YOU MUST CONSTRUCT ADDITIONAL PYLONS\n")
	my_sock.sendto(data, (dst_ip, dst_port))
	time.sleep(1)
        #num += 1

my_sock.close()

import socket

def tcp_single_send(target_ip, target_port):

  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # tcp socket
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # reuse addr
  sock.connect((target_ip, target_port)) # connect

  sock.send("I am a packet")
  #sock.shutdown(socket.SHUT_WR)

  #time.sleep(2)
  sock.close()

def udp_single_send(target_ip, target_port):

  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # reuse addr
  
  #sock.connect((target_ip, target_port))

  sock.sendto("I am a packet",(target_ip, target_port))
  #sock.shutdown(socket.SHUT_WR)

  #time.sleep(2)
  sock.close()


#tcp_single_send("127.0.0.1", 4444)
udp_single_send("127.0.0.1", 4444)

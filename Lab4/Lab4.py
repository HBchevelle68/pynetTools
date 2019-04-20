import cno_net_helper      as cno
#import cno_net_helper_ipv6 as cnosix
import helper_functions    as hf
import netaddr_convert     as nc
import struct
import socket
import time


def tcp_single_send(target_ip, target_port):

  sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM) # tcp socket
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # reuse addr
  sock.bind(('',31337))
  sock.connect((target_ip, target_port)) # connect
  
  #request = socket.htonl(66051)

  sock.send("\x00\x01\x02\x03")
  sock.shutdown(socket.SHUT_WR)
  print sock.recv(1024)
  time.sleep(1)
  sock.shutdown(socket.SHUT_RD)
  sock.close()

def udp_single_send(target_ip, target_port):

  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # reuse addr
  
  #sock.connect((target_ip, target_port))

  sock.sendto("I am a packet",(target_ip, target_port))
  #sock.shutdown(socket.SHUT_WR)

  time.sleep(2)
  sock.close()


def tcp_server(port):

  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # tcp socket
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # reuse addr
  sock.bind(('', port)) # bind
  sock.listen(5) # listen

  while 1:
    conn, addr = sock.accept()
    print "Connected by ", addr
    msg = conn.recv(1000)
    if msg:
      print msg
    conn.close()

  sock.close()

def udp_server(port):

  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # tcp socket
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # reuse addr
  sock.bind(('', port)) # bind

  while 1:
    msg, addr = sock.recvfrom(1000)
    print "UDP Message from ", addr
    if msg:
      print msg
    
  sock.close()



#a:c:7:9:1098:e674:62fd:5f2

tcp_single_send("a:c:7:9::20", 9999)
#udp_single_send("127.0.0.1", 4444)

#tcp_server(4444)
#udp_server(4444)

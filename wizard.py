#############################
#                           #
#           Incomplete      #
#                           #
#############################
import net_helper as nh
import socket
import argparse
import threading
import time



## PORT TYPE
def port_type(val):
  assert type(val) == str
  if '-' in val:
    tmp = val.split('-')
    return range(int(tmp[0]),int(tmp[1])+1)
  else:
    return int(val)

## ARGUMENT PARSER
def get_args():
  parser = argparse.ArgumentParser()
  parser.add_argument('-i', '--ip', type=str, required=True, help="Target IP")
  parser.add_argument('-p', '--ports', type=port_type, help="Port range")
  parser.add_argument('-u', '--udp', action ='store_true', help='Use UDP Scan')
  parser.add_argument('-c', '--connect', action ='store_true', help='Use TCP Connect Scan')
  parser.add_argument('-s', '--syn', action ='store_true', help='Use TCP SYN Scan')
  parser.add_argument('-a', '--ack', action ='store_true', help='Use TCP ACK Scan')
  return parser.parse_args()

## CONNECT SCAN

def conn_scan(ip_addr, port_start=0, port_end=0):
  
  openlist = []
  ret = 0 
  if port_start and port_end:
    print "%d, %d" % (port_start, port_end)
    for port in xrange(port_start,port_end): 
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      sock.settimeout(.001)
      try:
        ret = sock.connect_ex((ip_addr, port))
        #time.sleep(.25)
      except socket.error as msg:
        print msg
        sock.close()
        continue
      finally:
        if ret == 0:
          sock.close()
          openlist.append(port)
  
  elif port_start:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(.001)
    try: 
        ret = sock.connect_ex((ip_addr, port_start))
        #time.sleep(1)
    except socket.error as msg:
        print msg
        sock.close()
    finally:
      if ret == 0:
        sock.close()
        openlist.append(port_start)
  else:
    for port in xrange(1,65535):
      print port
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
      sock.settimeout(.001)
      try: 
        ret = sock.connect_ex((ip_addr, port))
        #time.sleep(.1)
      except socket.error as msg:
        sock.close()
        continue
      finally:
        if ret == 0:
          #print "OPEN"
          sock.close()
          openlist.append(port) 
  
  sock.close()
  return openlist


########################################################################

if __name__ == '__main__':
  args = get_args()

  if args.connect:
    if args.ports:
      if type(args.ports) == int:
        openports = conn_scan(args.ip, int(args.ports))
        print "open ports - ", openports
      else:
        #print args.ports
        openports = conn_scan(args.ip, args.ports[0], args.ports[-1])
        print "open ports - ", openports
    else:
      openports = conn_scan(args.ip)
      print "open ports - ", openports

    

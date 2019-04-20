import socket
import struct
import sys
import threading

names = {}

def sendmsg(msg):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 5)
    sock.sendto(msg, ("ff02::12:12:12", 10000))
    sock.close()

def recvmsg():
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    group_bin = socket.inet_pton(socket.AF_INET6, "ff02::12:12:12")
    group = group_bin + struct.pack('@I', 0)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, group)
    sock.bind(("", 10000))
    while True:
        data, sender = sock.recvfrom(1024)
        while data[-1:] == '\0':
            data = data[:-1]
        if data.split()[0] == ":change_name":
            if data.split()[1][:30] not in names.values():
                names[sender[0]] = data.split()[1][:30]
        else:
            if names.has_key(sender[0]):
                print (names[sender[0]] + ':   ' + repr(data))
            else:
                print (str(sender) + ':   ' + repr(data))

print "Type command ':name <username>' to change your display name!"
print "Type ':users' to get a list of users."
print "Type ':version' to get the version."
print "The display name can be up to 30 characters, no spaces."

th = threading.Thread(target=recvmsg)
th.daemon = True
th.start()
while True:
    msg = raw_input()
    if msg.split() == []:
        continue
    if msg.split()[0] == ":name":
        args = msg.split()
        if len(args) > 1:
            if args[1] in names:
                print "Please choose a unique name"
            else:
                sendmsg(":change_name " + args[1])
        else:
            print "Please provide a name"
    elif msg.split()[0] == ":users":
        for i in names.values():
            print i
    elif msg.split()[0] == ":version":
        print "who cares?"
    else:
        sendmsg(msg)


# str----byte_list
# \	    /
#  \       /
#   \     /
#    \   /
#     \ /
#      V
#    long

# MAC Address helper funcs (works for 48-bit addrs)

# MAC Addr String -> Byte List
def matob(mac_str):
	return [int(x,16) for x in mac_str.split(":")]
# MAC Addr String -> Int
def matoi(mac_str):
	return sum([int(x,16) << (8*i) for x,i in zip(mac_str.split(":"),range(len(mac_str.split(":"))-1,-1,-1))])
# MAC Addr Byte List -> String
def mbtoa(mac_bytes):
	return ":".join(["%02x" % x for x in mac_bytes])

# MAC Addr Byte List -> Int
def mbtoi(mac_bytes):
	return sum([x << (8*i)  for x,i in zip(mac_bytes,range(len(mac_bytes),0,-1))])

# MAC Addr Int -> String
def mitoa(mac_long):
	return ":".join([("%02x" % (((mac_long % (256**i)) >> (8*(i-1))))) for i in range(6,0,-1)])

# MAC Addr Int -> Byte List
def mitob(mac_long):
	return [(mac_long % (256**i)) >> (8*(i-1)) for i in range(6,0,-1)]

# IP Address helper funcs

# IP Addr String -> Byte List
def ipatob(ip_str):
	return [int(x) for x in ip_str.split(".")]

# IP Addr String -> Int
def ipatoi(ip_str):
	return sum([int(x) << (8*i) for x,i in zip(ip_str.split("."),range(len(ip_str.split("."))))])

# IP Addr Byte List -> String
def ipbtoa(ip_bytes):
	return ".".join([str(x) for x in ip_bytes])

# IP Addr Byte List -> Int
def ipbtoi(ip_bytes):
	return sum([x << (8*i) for x,i in zip(ip_bytes, range(len(ip_bytes)))])

# IP Addr Int -> String
def ipitoa(ip_long):
	return ".".join([str((ip_long % 256**i) >> (8*(i-1))) for i in range(1,5)])

# IP Addr Int -> Byte List
def ipitob(ip_long):
	return [(ip_long % 256**i) >> (8*(i-1)) for i in range(1,5)]

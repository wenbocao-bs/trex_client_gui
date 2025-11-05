# utils/helpers.py
import socket
import struct

def ip_to_int(ip: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def int_to_ip(i: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", i))

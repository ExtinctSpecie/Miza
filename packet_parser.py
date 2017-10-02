import socket
import struct
from binascii import hexlify

class Super(object):
    @wow
    def say_hello(self):
        print("Hello")


class Packet_Parser(Super):

    sniff = True

    def __init__(self):
        pass
        #self.start_sniffing()
    
    def say_hello(self):
        print("hi")

    def ethernet_frame(self,raw_data):

        dest, src, prototype = struct.unpack('! 6s 6s 2s', raw_data[:14])
        self.dest_address = self.format_mac_address(hexlify(dest))
        self.src_address = self.format_mac_address(hexlify(src))
        self.ether_type = hexlify(prototype)
        self.packet_data = raw_data[14:]

        return self.dest_address , self.src_address , self.ether_type , self.packet_data


    def sniff_packet(self):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        dest, src, proto, data = self.ethernet_frame(s.recvfrom(65565)[0])

        print(dest, src, int(proto, 16))
        print(proto[::1])

    def stop_sniffing(self):
        self.sniff = False

    def format_mac_address(self, hex_mac):

        return '-'.join(odd_char + even_char for odd_char, even_char in zip(hex_mac[::2], hex_mac[1::2]))


import socket
import struct
from binascii import hexlify


class Packet_Parser(object):

    _0x0800 = 2048
    _0x0806 = 2054

    def __init__(self):
        pass
        #self.start_sniffing()

    def ethernet_frame(self,raw_data):

        dest, src, prototype = struct.unpack('! 6s 6s 2s', raw_data[:14])
        self.dest_address = self.format_mac_address(hexlify(dest))
        self.src_address = self.format_mac_address(hexlify(src))
        self.ether_type = hexlify(prototype)
        self.packet_data = raw_data[14:]

        print('Source Mac Address ~~> {}\nDestination Mac Address ~~> {}\nEthernet Type ~~> {}'.format(self.src_address,self.dest_address,self.ether_type))
        print("\n#######################################################################################################\n")

        return self.dest_address , self.src_address , self.ether_type , self.packet_data


    def sniff_packet(self):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        dest, src, proto, byte_data = self.ethernet_frame(s.recvfrom(65565)[0])

        if(int(proto,16) == self._0x0800 ):
            self.ipv4_packet(byte_data)

        #print(proto[1::2])
    def ipv4_packet(self,byte_data):
        #version_header = hexlify(struct.unpack('! 1s',byte_data[0]))
        #version = version_header >> 4
        #header_length = (version_header & 15) * 4
        #ttl, proto, src, target = struct.unpack('! 8x BB 2x 4s 4s', byte_data[:20])
        ###
        #each byte is described by 2 hex numbers IP Header = 20 bytes
        #20*2 = 40
        ###
        hex_data = hexlify(byte_data[:40])
        # version = hex_data[:4]
        # header_length = hex_data[4:8]
        # dscp = hex_data[8:14]
        # ecn = hex_data[14:16]
        # total_length = hex_data[16:32]
        # identification = hex_data[32:48]
        # flags = hex_data[48:51]
        # fragment_offset = hex_data[51:64]
        # time_to_live = ttl = hex_data[64:72]
        # protocol = hex_data[72:80]
        # header_checksum = hex_data[80:96]
        # source_ip_address = hex_data[96:128]
        # destionation_ip_address = hex_data[128:160]
        source_ip_address = hex_data[24:32]
        destionation_ip_address = hex_data[32:40]
        ttl = hex_data[8:9]


        self.dec_ip_address(source_ip_address)
        print('\nSIP : {}\nDIP : {}\nTTL : {}\nDATA : {}'.format(source_ip_address,destionation_ip_address,ttl,hex_data))
        #print(version,header_length,ttl,proto,src,target)
    def stop_sniffing(self,byte_data):

        self.sniff = False

    def dec_ip_address(self,hex_ip):

        pair_ip = [odd_char + even_char for odd_char, even_char in zip(hex_ip[::2], hex_ip[1::2])]
        print([int(x,16) for x in pair_ip])
        dec_ip = [x for x in hex_ip[::1]]
        print(dec_ip)

        #return ':'.join( (odd_char + even_char for odd_char, even_char in zip(hex_ip[::2], hex_ip[1::2]) for int(odd_char + even_char,16) in odd_char+even_char) )


    def format_mac_address(self, hex_mac):

        return ':'.join(odd_char + even_char for odd_char, even_char in zip(hex_mac[::2], hex_mac[1::2]))


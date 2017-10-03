from packet_parser import *



d = Packet_Parser()


try:
    print("\n#######################################################################################################\n")
    while True:
        d.sniff_packet()
except KeyboardInterrupt as e:
    print(e , " WTFF ")




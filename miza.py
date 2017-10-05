from packet_parser import *



d = Packet_Parser()


try:
   while True:
    print("\n#######################################################################################################\n")

    d.sniff_packet()
except KeyboardInterrupt as e:
    print(e , " WTFF ")




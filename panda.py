from scapy.all import *
import csv
from packet import Packet
class Panda:
    def __init__(self):
        self.read()
        self.open()

    def read(self):
        self.packets = rdpcap('captured_packets.pcap')

    def open(self):
        with open('pandas_data.csv', mode='w', newline='') as file:
            # Tạo đối tượng writer
            writer = csv.writer(file)
            writer.writerow(
                ['Source Address', 'Destination Address', 'Source Port', 'Destination Port', 'Length', 'Protol'])
            for packet in self.packets:
                hex_data = hexdump(packet, dump=True)
                list_data = hex_data.split("\n")
                data = ""
                for list in list_data:
                    data += list[6:53] + " "
                data = data.replace(" ", "")
                packet = Packet(data)
                src_a = packet.src_addr_ip
                dst_a = packet.dst_addr_ip
                lenght = packet.size
                protol = packet.protol
                src_p = packet.src_port_tup
                dst_p = packet.dst_port_tup
                writer.writerow([src_a, dst_a, src_p, dst_p, lenght, protol])
class Packet:
    def __init__(self, pkg):
        self.data = pkg
        self.ethernet = self.analyze_ether_header(self.data)
        self.ip = self.analyze_ip_header(self.data)
        if self.next_proto == "TCP":
            self.tup = self.analyze_tcp_header(self.data)
        elif self.next_proto == "UDP":
            self.tup = self.analyze_udp_header(self.data)
        else:
            self.tup = "-----------------------------------------------" + "\n" + \
                       "                     Other                     " + "\n" + \
                       "-----------------------------------------------"
        self.size = self.tot_len
        self.src_addr_ip = self.src_addr
        self.dst_addr_ip = self.dst_addr
        if self.next_proto != "Other":
            self.src_port_tup = self.src_port
            self.dst_port_tup = self.dst_port
        else:
            self.src_port_tup = "Other"
            self.dst_port_tup = "Other"
        self.protol = self.next_proto

    def infor(self):
        return self.ethernet + "\n" + self.ip + "\n" + self.tup

    def analyze_ether_header(self, data):
        self.dest_mac = data[0:12]
        self.src_mac = data[12:24]
        self.proto = data[24:28]
        self.data = data[28:]
        if self.proto == "0800":
            self.proto_ip = "IP4"
        else:
            self.proto_ip = "IP6"
        self.eth = "-----------------ETHERNET------------------" +  "\n"  \
                    "Destination MAC: "+  str(self.MAC(self.dest_mac)) + "\n"  \
                    "Source MAC: "+ str(self.MAC(self.src_mac)) + "\n"  \
                    "Protol: "+ str(self.proto_ip)
        return self.eth

    def MAC(self, data):
        s = ""
        count = 0
        for i in data:
            if count == 2:
                s += ":"
                count = 0
            count += 1
            s += i
        return s

    def value_flags(self, n):
        hex_value = str(n)
        binary_value = bin(int(hex_value, 16))[2:].zfill(8)  # zfill để đảm bảo chuỗi đầu ra có 8 ký tự
        return int(str(binary_value)[4:7], 2)

    def analyze_ip_header(self, data):
        self.ver = str(data)[0]
        self.ihl = int(str(data)[1], 16) * 4
        self.tos = "0x" + data[2:4]
        self.tot_len = str(int(data[4:8], 16))
        self.ip_id = "0x" + self.data[8:12]
        self.flags = "0x" + str(int(bin(int(data[12], 16))[2:].zfill(4)[0:3], 2))
        self.frags_offset = int(bin(int(data[12], 16))[2:].zfill(4)[3] + bin(int(data[13], 16))[2:].zfill(4) + \
                           bin(int(data[14], 16))[2:].zfill(4) + bin(int(data[15], 16))[2:].zfill(4), 2)
        self.ip_ttl = int(data[16:18], 16)
        self.ip_proto = int(data[18:20], 16)
        self.chk_sum = "0x" + data[20:24]
        self.src_addr = str(int(data[24:26], 16)) + "." + str(int(data[26:28], 16)) + \
                   "." + str(int(data[28:30], 16)) + "." + str(int(data[30:32], 16))
        self.dst_addr = str(int(data[32:34], 16)) + "." + str(int(data[34:36], 16)) + \
                   "." + str(int(data[36:38], 16)) + "." + str(int(data[38:40], 16))
        if self.ip_proto == 6:
            self.next_proto = "TCP"
        elif self.ip_proto == 17:
            self.next_proto = "UDP"
        else:
            self.next_proto = "Other"
        self.data = data[40:]
        self.ip = "----------------------IP-----------------------" + "\n" + \
            "Version: " + str(self.ver) + "\n" + \
            "IHL: " + str(self.ihl) + "\n" + \
            "Type of Service: " + str(self.tos) + "\n" + \
            "Total Length: " + str(self.tot_len) + " (bytes)" + "\n" + \
            "Identification: " + str(self.ip_id) + "\n" + \
            "Flags: " + str(self.flags) + "\n" + \
            "Framgment Offset: " + str(self.frags_offset) + "\n" + \
            "Time To Live: " + str(self.ip_ttl) + "\n" + \
            "Protocol: " + str(self.ip_proto) + "\n" + \
            "Header Checksum: " + str(self.chk_sum) + "\n" + \
            "Source Address: " + str(self.src_addr) + "\n" + \
            "Destination Address: " + str(self.dst_addr)
        return self.ip

    def analyze_tcp_header(self, data):
        self.src_port = int(data[0:4], 16)
        self.dst_port = int(data[4:8], 16)
        self.seq_num = int(data[8:16], 16)
        self.ack_num = int(data[16:24], 16)
        self.data_offset = str(int(data[24], 16) * 4) + " (bytes)"
        self.reserved = bin(int(data[25], 16))[2:].zfill(4) + bin(int(data[26], 16))[2:].zfill(4)[0:2]
        self.flags = bin(int(data[26], 16))[2:].zfill(4)[2:] + bin(int(data[27], 16))[2:].zfill(4)
        self.urg = self.flags[0]
        self.ack = self.flags[1]
        self.psh = self.flags[2]
        self.rst = self.flags[3]
        self.syn = self.flags[4]
        self.fin = self.flags[5]
        self.windows = int(data[28:32], 16)
        self.checksum = "0x" + data[32:36]
        self.urg_ptr = int(data[36:40], 16)
        self.data = data[40:]
        self.tcp = "---------------------TCP-----------------------" + "\n" +\
            "Source Port: " + str(self.src_port) + "\n" + \
            "Destination Port: " + str(self.dst_port) + "\n" + \
            "Sequence Number: " + str(self.seq_num) + "\n" + \
            "Acknowledgment Number: " + str(self.ack_num) + "\n" + \
            "Data Offset: " + str(self.data_offset) + "\n" + \
            "Reserved: " + str(self.reserved) + "\n" + \
            "Flags: " + str(self.flags) + "\n" + \
            "URG: " + str(self.urg) + "\n" + \
            "ACK: " + str(self.ack) + "\n" + \
            "PSH: " + str(self.psh) + "\n" + \
            "RST: " + str(self.rst) + "\n" + \
            "SYN: " + str(self.syn) + "\n" + \
            "FIN: " + str(self.fin) + "\n" + \
            "Windows: " + str(self.windows) + "\n" + \
            "Checksum: " + str(self.checksum) + "\n" + \
            "Urgent Pointer: " + str(self.urg_ptr) + "\n" + \
            "-----------------------------------------------"
        return self.tcp

    def analyze_udp_header(self, data):
        self.src_port = int(data[0:4], 16)
        self.dst_port = int(data[4:8], 16)
        self.length = int(data[8:12], 16)
        self.chk_sum = "0x" + data[12:16]
        self.udp = "-------------------UDP-------------------------" + "\n" + \
            "Source Port: " + str(self.src_port) + "\n" + \
            "Destination Port: " + str(self.dst_port) + "\n" + \
            "Length: " + str(self.length) + " (bytes)" +  "\n" + \
            "Checksum: " + str(self.chk_sum) + "\n" + \
            "--------------------------------------------------"
        self.data = data[16:]
        return self.udp

    def __str__(self):
        return self.ethernet + "\n" + self.ip + "\n" + self.tup
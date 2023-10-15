import pandas as pd
import matplotlib.pyplot as plt
from panda import Panda
import socket

class Infor:
    def __init__(self):
        panda = Panda()
        panda.read()
        panda.open()
        self.data = pd.read_csv('pandas_data.csv')
        self.count = self.count_connect()
        self.ip_addr = self.ip_wifi()
        self.cb = self.max_connect()
        # self.cb = "Hiển thị"

    def ip_wifi(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address

    def chart(self):
        grouped = self.data.groupby(['Protol'])
        count = grouped.size()
        count_df = count.reset_index(name='count')
        proto = count_df.iloc[:, 0]
        value = count_df.iloc[:, 1]
        label = [proto[0], proto[1], proto[2]]
        list_value = [value[0], value[1], value[2]]
        plt.pie(list_value, labels=label, autopct='%1.1f%%')
        plt.show()


    def count_connect(self):
        grouped = self.data.groupby(["Source Address", "Destination Address"])
        count = grouped.size()
        count_df = count.reset_index(name='count')
        self.src_addr_values = count_df.iloc[:, 0]
        self.dst_addr_values = count_df.iloc[:, 1]
        self.count_values = count_df.iloc[:, 2]
        self.kq = ""
        for i in range(len(self.src_addr_values)):
            self.kq += "{:<15} -> {:<15} có {}\n".format(str(self.src_addr_values[i]), str(self.dst_addr_values[i]), str(self.count_values[i]))
        return self.kq

    def max_connect(self):
        list_addr = ""
        for i in range(len(self.dst_addr_values)):
            if self.dst_addr_values[i] == self.ip_addr:
                list_addr += "{} -> {} có {}\n".format(str(self.src_addr_values[i]), str(self.dst_addr_values[i]), str(self.count_values[i]))
        if len(list_addr) == 0:
            return "Không có kết nối nào!"
        return list_addr
        # list = []
        # list_count = []
        # for i in range(len(self.dst_addr_values)):
        #     if self.dst_addr_values[i] == self.ip_addr:
        #         list.append(i)
        #         list_count.append(int(self.count_values[i]))
        # if len(list_count) == 0:
        #     return "Không dữ liệu"
        # m_c = max(list_count)
        # list_addr = ""
        # for i in list:
        #     if self.count_values[i] == m_c:
        #         list_addr += "Từ {} đến {} có {} lần kết nối\n".format(str(self.src_addr_values[i]), str(self.dst_addr_values[i]), str(self.count_values[i]))
        # if list_addr != "":
        #     return list_addr
        # return "Không có kết nối nào đến máy hiện tại!"

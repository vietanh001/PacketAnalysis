from scapy.all import *
from PyQt5 import QtWidgets, QtGui
from PyQt5.QtWidgets import QApplication, QDesktopWidget, QTableWidget, QLineEdit, QPushButton, QFileDialog, QTextEdit, QTableWidgetItem, QVBoxLayout
import scapy.all as scapy
from packet import Packet
from panda import Panda
from infor import Infor
import csv
import matplotlib.pyplot as plt

class MainWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        font = QtGui.QFont()
        font.setPointSize(14)
        self.setWindowTitle("Phân tích gói tin mạng")
        self.resize(1200, 850)
        self.center()
        x = 360

        # Hiển thị địa chỉ IP Wi-Fi đang bắt
        self.text_ip = QTextEdit(self)
        self.text_ip.setGeometry(50, 20, 200, 40)
        font.setPointSize(12)
        self.text_ip.setFont(font)
        self.text_ip.setStyleSheet("border: 1px solid black")
        infor = Infor()
        self.text_ip.setReadOnly(True)
        self.text_ip.setPlainText("IP: " + str(infor.ip_addr))

        # Tạo nút để mở tệp
        self.openFileButton = QPushButton('Mở tệp', self)
        self.openFileButton.setFont(font)
        self.openFileButton.setGeometry(x - 80, 20, 100, 40)
        self.openFileButton.setStyleSheet("background-color: #33FFFF; border-radius: 20px; border: 1px solid black;")
        self.openFileButton.clicked.connect(self.openFile)

        # Thêm QLineEdit và QPushButton
        self.num_packets_edit = QLineEdit(self)
        font.setPointSize(13)
        self.num_packets_edit.setFont(font)
        self.num_packets_edit.setStyleSheet("border: 1px solid black; padding-left: 10px; border-radius: 20px")
        self.num_packets_edit.setPlaceholderText("Nhập số gói tin")
        self.num_packets_edit.move(x + 70, 20)
        self.num_packets_edit.resize(180, 40)

        # Thêm nút bắt gói tin
        self.start_sniff_button = QPushButton("Quét gói tin", self)
        font.setPointSize(14)
        self.start_sniff_button.setFont(font)
        self.start_sniff_button.setStyleSheet("background-color: #33FFFF; border-radius: 20px; border: 1px solid black;")
        self.start_sniff_button.move(x + 260, 20)
        self.start_sniff_button.resize(140, 40)
        self.start_sniff_button.clicked.connect(self.start_sniff)

        #Thêm nút chuyển sang dữ liệu csv
        self.csv_button = QPushButton("Chuyển dữ liệu", self)
        font.setPointSize(14)
        self.csv_button.setFont(font)
        self.csv_button.setStyleSheet("background-color: #33FFFF; border-radius: 20px; border: 1px solid black;")
        self.csv_button.move(x + 450, 20)
        self.csv_button.resize(200, 40)
        self.csv_button.clicked.connect(self.csv_table)

        z = 200

        # Thêm nút biểu đồ
        self.button_radius = QPushButton("Biểu đồ tròn về giao thức", self)
        font.setPointSize(14)
        self.button_radius.setFont(font)
        self.button_radius.setStyleSheet("background-color: #33FFFF; border-radius: 20px; border: 1px solid black;")
        self.button_radius.move(z, 790)
        self.button_radius.resize(350, 50)
        self.button_radius.clicked.connect(self.chart_radius)

        # Thêm nút đếm số kết nối
        self.button_connect_count = QPushButton("Số kết nối", self)
        font.setPointSize(14)
        self.button_connect_count.setFont(font)
        self.button_connect_count.setStyleSheet("background-color: #33FFFF; border-radius: 20px; border: 1px solid black;")
        self.button_connect_count.move(z + 360, 790)
        self.button_connect_count.resize(150, 50)
        self.button_connect_count.clicked.connect(self.conn_count)

        # Thêm nút cảnh báo kết nối đến máy nhiều nhất
        self.button_max_connect = QPushButton("Cảnh báo kết nối", self)
        font.setPointSize(14)
        self.button_max_connect.setFont(font)
        self.button_max_connect.setStyleSheet(
            "background-color: #33FFFF; border-radius: 20px; border: 1px solid black;")
        self.button_max_connect.move(z + 520, 790)
        self.button_max_connect.resize(200, 50)
        self.button_max_connect.clicked.connect(self.max_connect)

        # Tạo bảng hiện thị các gói tin
        self.packet_table = QTableWidget(self)
        self.packet_table.setGeometry(50, 80, 1100, 700)
        self.packet_table.setColumnCount(1)
        self.packet_table.setHorizontalHeaderLabels(["GÓI TIN"])
        header_font = QtGui.QFont()
        header_font.setPointSize(14)
        header = self.packet_table.horizontalHeader()
        header_font.setBold(True)
        font.setFamily("Console")
        header.setFont(header_font)
        header.setFont(font)
        self.packet_table.setColumnWidth(0, 1100)
        self.packet_table.itemClicked.connect(self.show_packet)

        self.packet_list = []

    def openFile(self):
        self.packet_table.setGeometry(50, 70, 1100, 700)
        self.packet_table.setColumnCount(1)
        self.packet_table.setHorizontalHeaderLabels(["GÓI TIN"])
        self.packet_table.setColumnWidth(0, 1100)
        fileName, _ = QFileDialog.getOpenFileName(self, 'Open File', '', 'Pcap files (*.pcap)')
        if fileName:
            packets = rdpcap(fileName)
            wrpcap('captured_packets.pcap', packets)
            self.read()
            self.packet_table.setRowCount(0)
            self.packet_table.setRowCount(int(len(packets)))
            for i in range(0, len(packets)):
                font = QtGui.QFont()
                font.setPointSize(14)
                item = QtWidgets.QTableWidgetItem(str(packets[i]))
                item.setFont(font)
                self.packet_table.setItem(i, 0, item)
            for row in range(int(len(self.packet_list))):
                if row % 2 == 0:
                    self.packet_table.item(row, 0).setBackground(QtGui.QColor("#F7D08A"))
                else:
                    self.packet_table.item(row, 0).setBackground(QtGui.QColor("#FFF1CF"))

    def start_sniff(self):
        # Xóa dữ liệu trên bảng hiện tại
        self.packet_table.setRowCount(0)
        self.packet_table.setColumnWidth(0, 1100)
        self.packet_table.setColumnCount(1)
        self.packet_table.setHorizontalHeaderLabels(["GÓI TIN"])
        # Lấy số gói tin từ QLineEdit
        num_packets = int(self.num_packets_edit.text())

        # Bắt dữ liệu gói tin
        packets = scapy.sniff(count=num_packets)
        scapy.wrpcap('captured_packets.pcap', packets)

        # Đọc dữ liệu
        self.read()

        # Thêm dữ liệu vào bảng
        font = QtGui.QFont()
        font.setPointSize(14)
        self.packet_table.setRowCount(int(len(self.packet_list)))
        for i in range(int(len(self.packet_list))):
            item = QtWidgets.QTableWidgetItem(str(self.packet_list[i]))
            item.setFont(font)
            self.packet_table.setItem(i, 0, item)
        for row in range(int(len(self.packet_list))):
            if row % 2 == 0:
                self.packet_table.item(row, 0).setBackground(QtGui.QColor("#F7D08A"))
            else:
                self.packet_table.item(row, 0).setBackground(QtGui.QColor("#FFF1CF"))

    def csv_table(self):
        panda = Panda()
        panda.open()
        panda.read()
        self.packet_table.setRowCount(0)
        self.packet_table.setColumnCount(6)
        self.packet_table.setHorizontalHeaderLabels(['Source Address', 'Destination Address', 'Source Port', 'Destination Port', 'Length', 'Protol'])

        self.read()
        with open('pandas_data.csv', newline='') as csvfile:
            reader = csv.reader(csvfile)
            data = list(reader)
            head = data.pop(0)
        self.packet_table.setRowCount(len(data))
        self.packet_table.setColumnWidth(0, 180)
        self.packet_table.setColumnWidth(1, 230)
        self.packet_table.setColumnWidth(2, 150)
        self.packet_table.setColumnWidth(3, 180)
        self.packet_table.setColumnWidth(4, 150)
        self.packet_table.setColumnWidth(5, 150)

        font = QtGui.QFont()
        font.setPointSize(12)
        for i, row in enumerate(data):
            for j, col in enumerate(row):
                item = QTableWidgetItem(col)
                item.setFont(font)
                self.packet_table.setItem(i, j, item)

        for row in range(int(len(self.packet_list))):
            if row % 2 == 0:
                self.packet_table.item(row, 0).setBackground(QtGui.QColor("#F7D08A"))
                self.packet_table.item(row, 1).setBackground(QtGui.QColor("#F7D08A"))
                self.packet_table.item(row, 2).setBackground(QtGui.QColor("#F7D08A"))
                self.packet_table.item(row, 3).setBackground(QtGui.QColor("#F7D08A"))
                self.packet_table.item(row, 4).setBackground(QtGui.QColor("#F7D08A"))
                self.packet_table.item(row, 5).setBackground(QtGui.QColor("#F7D08A"))
            else:
                self.packet_table.item(row, 0).setBackground(QtGui.QColor("#FFF1CF"))
                self.packet_table.item(row, 1).setBackground(QtGui.QColor("#FFF1CF"))
                self.packet_table.item(row, 2).setBackground(QtGui.QColor("#FFF1CF"))
                self.packet_table.item(row, 3).setBackground(QtGui.QColor("#FFF1CF"))
                self.packet_table.item(row, 4).setBackground(QtGui.QColor("#FFF1CF"))
                self.packet_table.item(row, 5).setBackground(QtGui.QColor("#FFF1CF"))

    def show_packet(self, item):
        row = item.row()
        pkt = self.packet_list_pcap[row]
        packet = Packet(pkt)
        dialog = QtWidgets.QDialog()
        dialog.setWindowTitle("Nội dung gói tin")
        dialog.resize(500, 700)
        scroll_area = QtWidgets.QScrollArea(dialog)
        font = QtGui.QFont()
        font.setPointSize(13)
        label = QtWidgets.QLabel(packet.infor(), dialog)
        label.setFont(font)
        label.move(20, 20)
        label.setWordWrap(True)  # Tự động xuống dòng khi vượt quá chiều rộng của QLabel
        scroll_area.setWidget(label)
        scroll_area.setGeometry(20, 20, 460, 660)
        dialog.exec_()

    def chart_radius(self):
        infor = Infor()
        grouped = infor.data.groupby(['Protol'])
        count = grouped.size()
        count_df = count.reset_index(name='count')
        proto = count_df.iloc[:, 0]
        value = count_df.iloc[:, 1]
        label = [proto[0], proto[1], proto[2]]
        list_value = [value[0], value[1], value[2]]
        plt.pie(list_value, labels=label, autopct='%1.1f%%')
        plt.show()

    def conn_count(self):
        dialog = QtWidgets.QDialog()
        dialog.setWindowTitle("Số kết nối")
        dialog.resize(500, 700)
        scroll_area = QtWidgets.QScrollArea(dialog)
        font = QtGui.QFont()
        font.setPointSize(13)
        infor = Infor()
        label = QtWidgets.QLabel(infor.count, dialog)
        label.setFont(font)
        label.move(20, 20)
        label.setWordWrap(True)  # Tự động xuống dòng khi vượt quá chiều rộng của QLabel
        scroll_area.setWidget(label)
        scroll_area.setGeometry(20, 20, 460, 660)
        dialog.exec_()

    def max_connect(self):
        dialog = QtWidgets.QDialog()
        dialog.setWindowTitle("Cảnh báo")
        dialog.resize(500, 700)
        scroll_area = QtWidgets.QScrollArea(dialog)
        font = QtGui.QFont()
        font.setPointSize(13)
        infor = Infor()
        label = QtWidgets.QLabel(infor.cb, dialog)
        label.setFont(font)
        label.move(20, 20)
        label.setWordWrap(True)  # Tự động xuống dòng khi vượt quá chiều rộng của QLabel
        scroll_area.setWidget(label)
        scroll_area.setGeometry(20, 20, 460, 660)
        dialog.exec_()

    def datax16(self, pkg):
        hex_data = hexdump(pkg, dump=True)
        list_data = hex_data.split("\n")
        data = ""
        for list in list_data:
            data += list[6:53] + " "
        data = data.replace(" ", "")
        return data

    def read(self):
        packets = rdpcap('captured_packets.pcap')
        self.packet_list = []
        self.packet_list_pcap = []
        for packet in packets:
            self.packet_list.append(packet.summary())
            self.packet_list_pcap.append(self.datax16(packet))

    def center(self):
        frame_geometry = self.frameGeometry()
        center_point = QDesktopWidget().availableGeometry().center()
        frame_geometry.moveCenter(center_point)
        self.move(frame_geometry.topLeft())

if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())
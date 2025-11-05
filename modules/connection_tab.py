# modules/connection_tab.py
# 连接配置标签页

from PyQt5.QtWidgets import QGroupBox, QVBoxLayout, QWidget, QHBoxLayout, QLabel, QLineEdit, QComboBox, QPushButton, QTextEdit
from PyQt5.QtCore import pyqtSignal
from .base_tab import BaseTab

class ConnectionTab(BaseTab):
    connected_signal = pyqtSignal()
    disconnected_signal = pyqtSignal()

    def __init__(self, controller, parent=None):
        super().__init__(controller, parent)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        group = QGroupBox("服务器设置")
        g_layout = QVBoxLayout()
        group.setLayout(g_layout)

        row = QHBoxLayout()
        row.addWidget(QLabel("服务器地址:"))
        self.server_input = QLineEdit("127.0.0.1")
        row.addWidget(self.server_input)
        g_layout.addLayout(row)

        ports_row = QHBoxLayout()
        ports_row.addWidget(QLabel("可用端口:"))
        self.ports_combo = QComboBox()
        self.ports_combo.addItems(["0", "1", "0,1"])
        ports_row.addWidget(self.ports_combo)
        g_layout.addLayout(ports_row)

        btn_row = QHBoxLayout()
        self.connect_btn = QPushButton("连接")
        self.connect_btn.clicked.connect(self.on_connect)
        btn_row.addWidget(self.connect_btn)
        self.disconnect_btn = QPushButton("断开")
        self.disconnect_btn.clicked.connect(self.on_disconnect)
        self.disconnect_btn.setEnabled(False)
        btn_row.addWidget(self.disconnect_btn)

        self.reset_btn = QPushButton("重置端口")
        self.reset_btn.clicked.connect(self.reset_ports)
        self.reset_btn.setEnabled(False)
        btn_row.addWidget(self.reset_btn)

        g_layout.addLayout(btn_row)

        self.status = QTextEdit()
        self.status.setReadOnly(True)
        self.status.setMaximumHeight(120)

        layout.addWidget(group)
        layout.addWidget(self.status)
        layout.addStretch()

    def update_ui_connected(self, connected: bool):
        self.reset_btn.setEnabled(connected)

    def append_status(self, text: str):
        self.status.append(text)
        if self.parent_window:
            try:
                self.parent_window.statusBar().showMessage(text, 5000)
            except Exception:
                pass

    def on_connect(self):
        server = self.server_input.text().strip()
        ok, msg = self.controller.connect(server=server)
        self.append_status(msg)
        if ok:
            self.connect_btn.setEnabled(False)
            self.disconnect_btn.setEnabled(True)
            self.connected_signal.emit()

    def on_disconnect(self):
        ok, msg = self.controller.disconnect()
        self.append_status(msg)
        if ok:
            self.connect_btn.setEnabled(True)
            self.disconnect_btn.setEnabled(False)
            self.disconnected_signal.emit()

    def reset_ports(self):
        ports = [int(p) for p in self.ports_combo.currentText().split(",")]
        success, message = self.controller.reset_ports(ports)
        self.status.append(message)

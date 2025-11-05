#!/usr/bin/env python3
# main.py - 程序入口，组装各模块标签页并启动应用

import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget, QVBoxLayout, QWidget
from trex_controller import TrexController
from modules.connection_tab import ConnectionTab
from modules.traffic_tab import TrafficTab
from modules.rfc2544_tab import Rfc2544Tab
from modules.stats_tab import StatsTab
from modules.log_tab import LogTab
from modules.capture_tab import CaptureTab

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("T-Rex 流量测试 - 模块化")
        self.resize(1300, 900)

        # controller shared by tabs
        self.controller = TrexController()

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout()
        central.setLayout(layout)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # instantiate tabs
        self.log_tab = LogTab(parent=self)
        self.connection_tab = ConnectionTab(self.controller, parent=self)
        self.traffic_tab = TrafficTab(self.controller, parent=self)
       # self.rfc2544_tab = Rfc2544Tab(self.controller, parent=self)
        self.stats_tab = StatsTab(self.controller, parent=self)
        self.capture_tab = CaptureTab(self.controller, parent=self)

        # add tabs
        self.tabs.addTab(self.connection_tab, "连接配置")
        self.tabs.addTab(self.traffic_tab, "流量配置")
        #self.tabs.addTab(self.rfc2544_tab, "RFC2544 测试")
        self.tabs.addTab(self.stats_tab, "统计信息")
        self.tabs.addTab(self.capture_tab, "数据包抓取")
        self.tabs.addTab(self.log_tab, "日志信息")

        # wire some callbacks
        # when connection established, allow other tabs to update UI
        self.connection_tab.connected_signal.connect(self.on_connected)
        self.connection_tab.disconnected_signal.connect(self.on_disconnected)

    def on_connected(self):
        self.log_message("连接成功")
        # enable capture/traffic/rfc tabs
        self.connection_tab.update_ui_connected(True)
        self.capture_tab.on_connection_state_changed()
        self.stats_tab.update_ui_connected(True)

    def on_disconnected(self):
        self.log_message("断开连接")
        self.connection_tab.update_ui_connected(False)
        self.capture_tab.on_connection_state_changed()
        self.stats_tab.update_ui_connected(False)

    def log_message(self, message: str, level: str = "信息"):
        # dispatch to log tab
        if hasattr(self, "log_tab"):
            try:
                self.log_tab.add_log_entry(message, level)
            except Exception:
                pass
        # also show in statusbar briefly
        self.statusBar().showMessage(f"[{level}] {message}", 5000)

def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()

# modules/capture_tab.py
# 数据包捕获标签页

from PyQt5.QtWidgets import (
    QVBoxLayout, QWidget, QGroupBox, QHBoxLayout, QLabel, QComboBox, QLineEdit,
    QPushButton, QSpinBox, QTextEdit, QFileDialog, QMessageBox
)
from PyQt5.QtCore import QTimer
import time
import os

class CaptureTab(QWidget):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.parent_window = parent
        self._build_ui()
        self.session_id = None
        self.captured_packets = []
        self.timer = QTimer()
        self.timer.timeout.connect(self._poll)

    def _build_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        group = QGroupBox("捕获控制")
        gl = QVBoxLayout()
        group.setLayout(gl)
        row = QHBoxLayout()
        row.addWidget(QLabel("捕获端口:"))
        self.port_combo = QComboBox(); self.port_combo.addItems(["0","1","0,1"])
        row.addWidget(self.port_combo)
        row.addWidget(QLabel("BPF:"))
        self.bpf = QLineEdit()
        row.addWidget(self.bpf)
        gl.addLayout(row)
        btn_row = QHBoxLayout()
        self.start_btn = QPushButton("开始捕获"); self.start_btn.clicked.connect(self.start_capture); self.start_btn.setEnabled(False)
        btn_row.addWidget(self.start_btn)
        self.stop_btn = QPushButton("停止捕获"); self.stop_btn.clicked.connect(self.stop_capture); self.stop_btn.setEnabled(False)
        btn_row.addWidget(self.stop_btn)
        self.export_btn = QPushButton("导出PCAP"); self.export_btn.clicked.connect(self.export_pcap); self.export_btn.setEnabled(False)
        btn_row.addWidget(self.export_btn)
        gl.addLayout(btn_row)
        self.list_text = QTextEdit(); self.list_text.setReadOnly(True); gl.addWidget(self.list_text)
        layout.addWidget(group)

    def on_connection_state_changed(self):
        self.start_btn.setEnabled(self.controller.is_connected)

    def start_capture(self):
        if not self.controller.is_connected:
            self.parent_window.log_message("未连接 T-Rex", "错误")
            return
        ports = [int(p) for p in self.port_combo.currentText().split(",") if p.strip().isdigit()]
        ok, sid = self.controller.start_capture(ports=ports, limit=0, bpf_filter=self.bpf.text() or None, mode='continuous')
        if not ok:
            self.parent_window.log_message(f"启动捕获失败: {sid}", "错误")
            return
        self.session_id = sid
        self.timer.start(1000)
        self.start_btn.setEnabled(False); self.stop_btn.setEnabled(True)
        self.parent_window.log_message(f"开始捕获 session={sid}", "信息")

    def _poll(self):
        if not self.session_id:
            return
        ok, pkts = self.controller.get_captured_packets(self.session_id)
        if ok and pkts:
            self.captured_packets.extend(pkts)
            self._refresh_list()

    def _refresh_list(self):
        self.list_text.clear()
        for i,p in enumerate(self.captured_packets):
            try:
                ln = len(p)
            except Exception:
                ln = 0
            self.list_text.append(f"{i+1}: len={ln}")

    def stop_capture(self):
        if not self.session_id:
            return
        ok, pkts = self.controller.stop_capture(self.session_id)
        if ok and pkts:
            self.captured_packets.extend(pkts)
        self.timer.stop()
        self.start_btn.setEnabled(True); self.stop_btn.setEnabled(False)
        self.export_btn.setEnabled(len(self.captured_packets) > 0)
        self.parent_window.log_message("已停止捕获", "信息")
        self._refresh_list()

    def export_pcap(self):
        if not self.captured_packets:
            return
        filename, _ = QFileDialog.getSaveFileName(self, "导出PCAP", f"capture_{int(time.time())}.pcap", "PCAP Files (*.pcap)")
        if not filename:
            return
        # try wrpcap if scapy available; controller may store raw bytes, so we fallback to raw write
        try:
            from scapy.all import wrpcap
            wrpcap(filename, self.captured_packets)
        except Exception:
            with open(filename, "wb") as f:
                for pkt in self.captured_packets:
                    try:
                        f.write(pkt)
                    except Exception:
                        pass
        self.parent_window.log_message(f"导出到 {filename}", "信息")

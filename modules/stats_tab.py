# modules/stats_tab.py
# 统计信息标签页

from PyQt5.QtWidgets import QVBoxLayout, QWidget, QTextEdit, QPushButton, QHBoxLayout, QLabel
from PyQt5.QtCore import QTimer
from .base_tab import BaseTab
import json

class StatsTab(BaseTab):
    def __init__(self, controller, parent=None):
        super().__init__(controller, parent)
        self._build_ui()
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh)

    def _build_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        self.display = QTextEdit()
        self.display.setReadOnly(True)
        layout.addWidget(self.display)
        row = QHBoxLayout()
        self.start_btn = QPushButton("开始监控"); self.start_btn.clicked.connect(self.start)
        self.stop_btn = QPushButton("停止监控"); self.stop_btn.clicked.connect(self.stop); self.stop_btn.setEnabled(False)
        row.addWidget(self.start_btn); row.addWidget(self.stop_btn)
        row.addWidget(QLabel("实时统计"))
        layout.addLayout(row)

    def update_ui_connected(self, connected: bool):
        self.start_btn.setEnabled(connected)

    def start(self):
        if not self.controller.is_connected:
            self.parent_window.log_message("未连接", "错误")
            return
        self.timer.start(1000)
        self.start_btn.setEnabled(False); self.stop_btn.setEnabled(True)

    def stop(self):
        self.timer.stop()
        self.start_btn.setEnabled(True); self.stop_btn.setEnabled(False)

    def refresh(self):
        stats = self.controller.get_stats()
        try:
            self.display.setPlainText(json.dumps(stats, indent=2, ensure_ascii=False))
        except Exception:
            self.display.setPlainText(str(stats))

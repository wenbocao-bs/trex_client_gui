# modules/log_tab.py
# 日志信息标签页

from PyQt5.QtWidgets import QVBoxLayout, QWidget, QTextEdit, QHBoxLayout, QLabel, QComboBox, QPushButton, QFileDialog, QCheckBox
from PyQt5.QtGui import QFont, QColor, QTextCursor
import datetime

class LogTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()
        self.entries = []

    def _build_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("日志级别:"))
        self.level_combo = QComboBox(); self.level_combo.addItems(["所有","调试","信息","警告","错误"])
        ctrl.addWidget(self.level_combo)
        self.pause_btn = QPushButton("暂停"); self.pause_btn.setCheckable(True); self.pause_btn.toggled.connect(self.on_pause)
        ctrl.addWidget(self.pause_btn)
        self.clear_btn = QPushButton("清除"); self.clear_btn.clicked.connect(self.clear)
        ctrl.addWidget(self.clear_btn)
        self.save_btn = QPushButton("保存"); self.save_btn.clicked.connect(self.save)
        ctrl.addWidget(self.save_btn)
        self.auto_scroll = QCheckBox("自动滚动"); self.auto_scroll.setChecked(True)
        ctrl.addWidget(self.auto_scroll)
        layout.addLayout(ctrl)

        self.text = QTextEdit(); self.text.setReadOnly(True)
        font = QFont("Courier New", 9); self.text.setFont(font)
        layout.addWidget(self.text)

    def on_pause(self, paused):
        self.paused = paused
        self.pause_btn.setText("继续" if paused else "暂停")

    def add_log_entry(self, message: str, level: str = "信息"):
        if getattr(self, "paused", False):
            return
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        line = f"[{ts}] [{level}] {message}"
        self.entries.append(line)
        if len(self.entries) > 10000:
            self.entries.pop(0)
        cur_level = self.level_combo.currentText()
        if cur_level != "所有" and cur_level != level:
            return
        cursor = self.text.textCursor()
        cursor.movePosition(QTextCursor.End)
        color_map = {"调试": QColor(100,100,100), "信息": QColor(0,0,0), "警告": QColor(255,165,0), "错误": QColor(255,0,0)}
        fmt = cursor.charFormat()
        fmt.setForeground(color_map.get(level, QColor(0,0,0)))
        cursor.setCharFormat(fmt)
        cursor.insertText(line + "\n")
        if self.auto_scroll.isChecked():
            self.text.moveCursor(QTextCursor.End)

    def clear(self):
        self.entries.clear()
        self.text.clear()

    def save(self):
        filename, _ = QFileDialog.getSaveFileName(self, "保存日志", f"trex_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", "Text Files (*.txt)")
        if filename:
            with open(filename, "w", encoding="utf-8") as f:
                for l in self.entries:
                    f.write(l + "\n")

# modules/base_tab.py
# 基础标签页类：提供常用工具/父类

from PyQt5.QtWidgets import QWidget
from typing import Optional

class BaseTab(QWidget):
    def __init__(self, controller, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.controller = controller
        self.parent_window = parent

    def log(self, message: str, level: str = "信息"):
        if hasattr(self.parent_window, "log_message"):
            self.parent_window.log_message(message, level)

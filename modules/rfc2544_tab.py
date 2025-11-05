# modules/rfc2544_tab.py
# RFC2544 测试标签页（增强版：使用 TrafficTab 中已定义的流配置自动按帧长/速率生成并发送）
#
# 改进点：
# - 在测试前从 controller.flow_configs 中读取用户在 TrafficTab 定义并保存的流配置（如果有）
# - 对每个帧长/速率，自动基于这些配置生成/下发流（覆盖 pkt_size 与 rate），分配唯一 PGID 并保存到 controller.flow_configs
# - 在未连接模式下回退为模拟（保持此前行为）
# - 对流的下发、启动、停止、清理做了更完善的错误处理与日志记录
# - 结果收集仍使用 controller.get_stats() / get_pgid_stats()，并写入表格与可导出 CSV
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QSpinBox, QDoubleSpinBox,
    QPushButton, QGroupBox, QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox, QFileDialog
)
from PyQt5.QtCore import QTimer, Qt
import time
import threading
import traceback
import csv
import json

# Optional TREX STL types
try:
    from trex.stl.api import STLStream, STLPktBuilder, STLTXCont, STLFlowStats
    TREX_STL_AVAILABLE = True
except Exception:
    STLStream = STLPktBuilder = STLTXCont = STLFlowStats = None
    TREX_STL_AVAILABLE = False

class Rfc2544Tab(QWidget):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.parent_window = parent
        self._build_ui()

        self.test_thread = None
        self.stop_requested = False
        self.results = []
        self.current_run = None
        self.ui_timer = QTimer()
        self.ui_timer.timeout.connect(self._refresh_ui_status)

    def _build_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        cfg_group = QGroupBox("RFC2544 配置")
        cl = QVBoxLayout()
        cfg_group.setLayout(cl)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("测试类型:"))
        self.test_type = QComboBox(); self.test_type.addItems(["吞吐量","时延","丢包率","背靠背"])
        row1.addWidget(self.test_type)

        row1.addWidget(QLabel("帧大小(可多选，用逗号或范围):"))
        self.frame_size_le = QComboBox()
        self.frame_size_le.setEditable(True)
        # default single sizes, user can type "64,128,256" or "64-1518"
        self.frame_size_le.addItems(["1518","64","128","256","512","1024","1280"])
        row1.addWidget(self.frame_size_le)

        cl.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("起始速率(%):"))
        self.start_rate = QDoubleSpinBox(); self.start_rate.setRange(0.1,100.0); self.start_rate.setValue(10.0)
        row2.addWidget(self.start_rate)
        row2.addWidget(QLabel("结束速率(%):"))
        self.end_rate = QDoubleSpinBox(); self.end_rate.setRange(0.1,100.0); self.end_rate.setValue(100.0)
        row2.addWidget(self.end_rate)
        row2.addWidget(QLabel("步进(%):"))
        self.step = QDoubleSpinBox(); self.step.setRange(0.1,50.0); self.step.setValue(10.0)
        row2.addWidget(self.step)
        cl.addLayout(row2)

        row3 = QHBoxLayout()
        row3.addWidget(QLabel("单次测试时长(秒):"))
        self.duration = QSpinBox(); self.duration.setRange(1,600); self.duration.setValue(10)
        row3.addWidget(self.duration)
        # binding/ports selection left to TrafficTab definitions; allow quick override
        row3.addWidget(QLabel("发送端口 (快速覆盖，可空使用 TrafficTab 已定义):"))
        self.send_ports_le = QComboBox()
        self.send_ports_le.addItems(["","0","1","0,1","0-1"])
        row3.addWidget(self.send_ports_le)
        row3.addWidget(QLabel("接收端口 (快速覆盖):"))
        self.recv_ports_le = QComboBox()
        self.recv_ports_le.addItems(["","1","0","0,1","0-1"])
        row3.addWidget(self.recv_ports_le)

        cl.addLayout(row3)

        btn_row = QHBoxLayout()
        self.start_btn = QPushButton("开始测试"); self.start_btn.clicked.connect(self.start_test)
        btn_row.addWidget(self.start_btn)
        self.stop_btn = QPushButton("停止测试"); self.stop_btn.clicked.connect(self.stop_test); self.stop_btn.setEnabled(False)
        btn_row.addWidget(self.stop_btn)
        self.export_btn = QPushButton("导出结果"); self.export_btn.clicked.connect(self.export_results); self.export_btn.setEnabled(False)
        btn_row.addWidget(self.export_btn)
        cl.addLayout(btn_row)

        layout.addWidget(cfg_group)

        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(12)
        self.results_table.setHorizontalHeaderLabels([
            "帧大小","速率(%)","发送端口","接收端口",
            "发送包数","接收包数","丢包数","丢包率(%)",
            "平均时延(μs)","最大时延(μs)","平均PPS","平均BPS"
        ])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.results_table)

        # Detailed stats display (JSON)
        self.detail_table = QTableWidget()
        self.detail_table.setColumnCount(2)
        self.detail_table.setHorizontalHeaderLabels(["指标","值"])
        labels = ["当前帧大小","当前速率","发送端口","接收端口","测试时长","发送包数","接收包数","丢包率","平均PPS","平均BPS"]
        self.detail_table.setRowCount(len(labels))
        for i,label in enumerate(labels):
            self.detail_table.setItem(i,0, QTableWidgetItem(label))
            self.detail_table.setItem(i,1, QTableWidgetItem("-"))
        self.detail_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.detail_table)

    # ---------------------------
    def _parse_ports(self, text):
        ports = []
        if not text:
            return ports
        s = str(text)
        for part in s.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                try:
                    a,b = part.split("-",1)
                    a=int(a); b=int(b)
                    ports.extend(list(range(a, b+1)))
                except Exception:
                    continue
            else:
                try:
                    ports.append(int(part))
                except Exception:
                    continue
        return sorted(list(set(ports)))

    def _parse_frame_sizes(self, text):
        """
        支持多种输入:
         - 单个数字 "1518"
         - 逗号分隔 "64,128,256"
         - 范围 "64-1518"
        返回整数列表（去重并排序）
        """
        s = str(text).strip()
        if not s:
            return []
        # if user selected an existing combobox item, it might be a single size
        parts = []
        if "," in s:
            parts = [p.strip() for p in s.split(",") if p.strip()]
        elif "-" in s and len(s.split("-"))==2:
            parts = [s]
        else:
            parts = [s]
        sizes = []
        for p in parts:
            if "-" in p:
                try:
                    a,b = p.split("-",1)
                    a=int(a); b=int(b)
                    # pick a small set: a, some midpoints, b? but RFC usually iterates by size list;
                    # here expand range by picking endpoints only to avoid too many sizes
                    sizes.extend([a,b])
                except Exception:
                    continue
            else:
                try:
                    sizes.append(int(p))
                except Exception:
                    continue
        sizes = sorted(list(set(sizes)))
        return sizes

    def start_test(self):
        if self.test_thread and self.test_thread.is_alive():
            QMessageBox.warning(self, "测试已在运行", "已有测试在运行中")
            return

        # gather config
        try:
            cfg = {}
            cfg['test_type'] = self.test_type.currentText()
            cfg['frame_sizes'] = self._parse_frame_sizes(self.frame_size_le.currentText())
            if not cfg['frame_sizes']:
                QMessageBox.warning(self, "帧大小", "请指定至少一个帧大小（可逗号分隔或范围）")
                return
            cfg['start_rate'] = float(self.start_rate.value())
            cfg['end_rate'] = float(self.end_rate.value())
            cfg['step'] = float(self.step.value())
            cfg['duration'] = int(self.duration.value())
            send_port_text = self.send_ports_le.currentText().strip()
            recv_port_text = self.recv_ports_le.currentText().strip()
            cfg['send_ports'] = self._parse_ports(send_port_text) if send_port_text else None
            cfg['recv_ports'] = self._parse_ports(recv_port_text) if recv_port_text else None
            # If cfg['send_ports'] is None, we'll use flows defined in controller.flow_configs to determine send ports
        except Exception as e:
            QMessageBox.critical(self, "参数错误", str(e))
            return

        # build rate list
        rates = []
        start = cfg['start_rate']; end = cfg['end_rate']; step = cfg['step']
        if start <= end:
            r = start
            while r <= end + 1e-9:
                rates.append(round(r,3))
                r += step
        else:
            r = start
            while r >= end - 1e-9:
                rates.append(round(r,3))
                r -= step
        if not rates:
            QMessageBox.warning(self, "速率错误", "无效速率范围")
            return

        # reset state
        self.results = []
        self.results_table.setRowCount(0)
        self.export_btn.setEnabled(False)
        self.stop_requested = False

        # start background worker
        self.test_thread = threading.Thread(target=self._run_full_rfc, args=(cfg, rates), daemon=True)
        self.test_thread.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.ui_timer.start(1000)
        self._log("RFC2544 测试启动", "信息")

    def stop_test(self):
        if not self.test_thread:
            return
        self.stop_requested = True
        self._log("停止请求已发送，等待线程结束...", "信息")
        self.ui_timer.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def _log(self, msg, level="信息"):
        if self.parent_window and hasattr(self.parent_window, "log_message"):
            try:
                self.parent_window.log_message(msg, level)
            except Exception:
                pass

    def _run_full_rfc(self, cfg, rates):
        """
        使用 TrafficTab 已定义的流作为模板：
          - 如果用户在 TrafficTab 已保存了多流（controller.flow_configs），
            将针对这些流在每个帧长/速率组合上生成新的流（覆盖 pkt_size 与 rate）并下发
          - 若 controller.flow_configs 不包含流或未连接到T‑Rex，则使用简单模板或模拟运行
        """
        try:
            # Determine send/recv ports: prefer cfg, otherwise derive from controller.flow_configs
            all_defined_send_ports = []
            if cfg.get('send_ports') is None:
                # derive unique send ports from controller.flow_configs keys
                try:
                    all_defined_send_ports = sorted([int(p) for p in self.controller.flow_configs.keys()])
                except Exception:
                    all_defined_send_ports = []
            else:
                all_defined_send_ports = cfg['send_ports']
        except Exception:
                print("asdfasdfasdf")

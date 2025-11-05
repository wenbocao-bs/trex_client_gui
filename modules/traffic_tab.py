# modules/traffic_tab.py
# 流量配置标签页（增强版：完整流构建 UI，与 TrexController.create_flow_template/_create_vm_for_random 对接）
#
# 新增：
# - 在界面中显示每个端口的流列表（flow_table）
# - 为每行添加“编辑 / 启动 / 停止 / 删除”操作列
# - 编辑功能会把选中流的参数载入表单进行修改并保存（下发或本地保存）
# - 启动/停止/删除会调用 controller 提供的相应接口并刷新显示
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QPushButton,
    QGroupBox, QSpinBox, QDoubleSpinBox, QLineEdit, QTextEdit, QTableWidget,
    QTableWidgetItem, QHeaderView, QCheckBox, QMessageBox, QWidgetItem, QSizePolicy
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
import traceback
import ipaddress
import time
from functools import partial

# T-Rex STL imports are optional — only used when connected to real T-Rex
try:
    from trex.stl.api import STLStream, STLPktBuilder, STLTXCont, STLFlowStats
    TREX_STL_AVAILABLE = True
except Exception:
    STLStream = STLPktBuilder = STLTXCont = STLFlowStats = None
    TREX_STL_AVAILABLE = False

class TrafficTab(QWidget):
    """
    TrafficTab provides a rich UI to construct flows, including randomization options,
    and will use TrexController.create_flow_template/_create_vm_for_random to build
    packet templates. It supports adding flows to selected ports (on-device) or saving
    them locally if not connected. Also lists existing flows per port with action buttons.
    """
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.parent_window = parent
        self.editing = None  # (port, index) if editing an existing flow
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        # Basic ethernet / flow identification
        eth_group = QGroupBox("基本以太网 / 流信息")
        eth_l = QVBoxLayout()
        eth_group.setLayout(eth_l)

        row = QHBoxLayout()
        row.addWidget(QLabel("流类型:"))
        self.flow_type_cb = QComboBox()
        self.flow_type_cb.addItems(["UDP", "TCP", "HTTP", "ICMP"])
        row.addWidget(self.flow_type_cb)

        row.addWidget(QLabel("流名称:"))
        self.flow_name_le = QLineEdit(f"flow_{int(time.time())}")
        row.addWidget(self.flow_name_le)
        eth_l.addLayout(row)

        mac_row = QHBoxLayout()
        mac_row.addWidget(QLabel("源MAC:"))
        self.src_mac_le = QLineEdit("00:03:00:01:40:01")
        mac_row.addWidget(self.src_mac_le)
        mac_row.addWidget(QLabel("目的MAC:"))
        self.dst_mac_le = QLineEdit("00:02:00:03:04:02")
        mac_row.addWidget(self.dst_mac_le)
        eth_l.addLayout(mac_row)

        layout.addWidget(eth_group)

        # IP / port configuration
        ip_group = QGroupBox("IP / 端口 配置")
        ip_l = QVBoxLayout()
        ip_group.setLayout(ip_l)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("源IP:"))
        self.src_ip_le = QLineEdit("16.0.0.1")
        row1.addWidget(self.src_ip_le)
        row1.addWidget(QLabel("目的IP:"))
        self.dst_ip_le = QLineEdit("48.0.0.1")
        row1.addWidget(self.dst_ip_le)
        ip_l.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("源端口:"))
        self.src_port_sb = QSpinBox(); self.src_port_sb.setRange(1, 65535); self.src_port_sb.setValue(1025)
        row2.addWidget(self.src_port_sb)
        row2.addWidget(QLabel("目的端口:"))
        self.dst_port_sb = QSpinBox(); self.dst_port_sb.setRange(1, 65535); self.dst_port_sb.setValue(80)
        row2.addWidget(self.dst_port_sb)
        ip_l.addLayout(row2)

        layout.addWidget(ip_group)

        # Randomization options
        rand_group = QGroupBox("随机化选项（可选）")
        rand_l = QVBoxLayout()
        rand_group.setLayout(rand_l)

        # source IP randomization
        sip_row = QHBoxLayout()
        self.rand_sip_cb = QCheckBox("随机源IP（网段）")
        sip_row.addWidget(self.rand_sip_cb)
        sip_row.addWidget(QLabel("开始:"))
        self.sip_start_le = QLineEdit("192.168.1.1")
        sip_row.addWidget(self.sip_start_le)
        sip_row.addWidget(QLabel("结束:"))
        self.sip_end_le = QLineEdit("192.168.1.100")
        sip_row.addWidget(self.sip_end_le)
        rand_l.addLayout(sip_row)

        # dst IP randomization
        dip_row = QHBoxLayout()
        self.rand_dip_cb = QCheckBox("随机目的IP（网段）")
        dip_row.addWidget(self.rand_dip_cb)
        dip_row.addWidget(QLabel("开始:"))
        self.dip_start_le = QLineEdit("192.168.2.1")
        dip_row.addWidget(self.dip_start_le)
        dip_row.addWidget(QLabel("结束:"))
        self.dip_end_le = QLineEdit("192.168.2.100")
        dip_row.addWidget(self.dip_end_le)
        rand_l.addLayout(dip_row)

        # random ports
        sport_row = QHBoxLayout()
        self.rand_sport_cb = QCheckBox("随机源端口")
        sport_row.addWidget(self.rand_sport_cb)
        sport_row.addWidget(QLabel("开始:"))
        self.sport_start_sb = QSpinBox(); self.sport_start_sb.setRange(1,65535); self.sport_start_sb.setValue(10000)
        sport_row.addWidget(self.sport_start_sb)
        sport_row.addWidget(QLabel("结束:"))
        self.sport_end_sb = QSpinBox(); self.sport_end_sb.setRange(1,65535); self.sport_end_sb.setValue(11000)
        sport_row.addWidget(self.sport_end_sb)
        rand_l.addLayout(sport_row)

        dport_row = QHBoxLayout()
        self.rand_dport_cb = QCheckBox("随机目的端口")
        dport_row.addWidget(self.rand_dport_cb)
        dport_row.addWidget(QLabel("开始:"))
        self.dport_start_sb = QSpinBox(); self.dport_start_sb.setRange(1,65535); self.dport_start_sb.setValue(20000)
        dport_row.addWidget(self.dport_start_sb)
        dport_row.addWidget(QLabel("结束:"))
        self.dport_end_sb = QSpinBox(); self.dport_end_sb.setRange(1,65535); self.dport_end_sb.setValue(21000)
        dport_row.addWidget(self.dport_end_sb)
        rand_l.addLayout(dport_row)

        # random packet size
        pkt_row = QHBoxLayout()
        self.rand_pkt_cb = QCheckBox("随机包长")
        pkt_row.addWidget(self.rand_pkt_cb)
        pkt_row.addWidget(QLabel("最小:"))
        self.pkt_min_sb = QSpinBox(); self.pkt_min_sb.setRange(64, 9000); self.pkt_min_sb.setValue(64)
        pkt_row.addWidget(self.pkt_min_sb)
        pkt_row.addWidget(QLabel("最大:"))
        self.pkt_max_sb = QSpinBox(); self.pkt_max_sb.setRange(64, 9732); self.pkt_max_sb.setValue(1518)
        pkt_row.addWidget(self.pkt_max_sb)
        rand_l.addLayout(pkt_row)

        layout.addWidget(rand_group)

        # VLAN / other settings
        misc_group = QGroupBox("其他设置")
        misc_l = QVBoxLayout()
        misc_group.setLayout(misc_l)

        vlan_row = QHBoxLayout()
        self.vlan_cb = QCheckBox("启用 VLAN")
        vlan_row.addWidget(self.vlan_cb)
        vlan_row.addWidget(QLabel("VLAN ID:"))
        self.vlan_id_sb = QSpinBox(); self.vlan_id_sb.setRange(1, 4094); self.vlan_id_sb.setValue(100)
        vlan_row.addWidget(self.vlan_id_sb)
        vlan_row.addWidget(QLabel("优先级:"))
        self.vlan_prio_sb = QSpinBox(); self.vlan_prio_sb.setRange(0,7); self.vlan_prio_sb.setValue(0)
        vlan_row.addWidget(self.vlan_prio_sb)
        misc_l.addLayout(vlan_row)

        size_row = QHBoxLayout()
        size_row.addWidget(QLabel("帧大小 (字节):"))
        self.pkt_size_sb = QSpinBox(); self.pkt_size_sb.setRange(64, 9732); self.pkt_size_sb.setValue(512)
        size_row.addWidget(self.pkt_size_sb)
        size_row.addWidget(QLabel("速率 (%):"))
        self.rate_ds = QDoubleSpinBox(); self.rate_ds.setRange(0.1, 100.0); self.rate_ds.setValue(10.0)
        size_row.addWidget(self.rate_ds)
        misc_l.addLayout(size_row)

        layout.addWidget(misc_group)

        # port selection & actions
        action_group = QGroupBox("目标端口与操作")
        action_l = QVBoxLayout()
        action_group.setLayout(action_l)

        top_row = QHBoxLayout()
        top_row.addWidget(QLabel("目标端口 (支持逗号/范围):"))
        self.target_ports_le = QLineEdit("0")
        top_row.addWidget(self.target_ports_le)

        top_row.addWidget(QLabel("查看端口:"))
        self.view_port_combo = QComboBox()
        self.view_port_combo.addItems(["0","1","2","3"])
        self.view_port_combo.currentIndexChanged.connect(self.on_view_port_changed)
        top_row.addWidget(self.view_port_combo)

        action_l.addLayout(top_row)

        btn_row = QHBoxLayout()
        self.add_to_device_btn = QPushButton("下发到 T-Rex 并保存")
        self.add_to_device_btn.clicked.connect(self.on_add_to_device)
        btn_row.addWidget(self.add_to_device_btn)

        self.save_local_btn = QPushButton("仅保存本地配置")
        self.save_local_btn.clicked.connect(self.on_save_local)
        btn_row.addWidget(self.save_local_btn)

        self.validate_btn = QPushButton("校验参数")
        self.validate_btn.clicked.connect(self.on_validate)
        btn_row.addWidget(self.validate_btn)

        self.save_changes_btn = QPushButton("保存变更")
        self.save_changes_btn.clicked.connect(self.on_save_changes)
        self.save_changes_btn.setEnabled(False)
        btn_row.addWidget(self.save_changes_btn)

        action_l.addLayout(btn_row)
        layout.addWidget(action_group)

        # flow list table (per view_port)
        list_group = QGroupBox("端口流列表")
        list_l = QVBoxLayout()
        list_group.setLayout(list_l)

        self.flow_table = QTableWidget()
        self.flow_table.setColumnCount(6)
        self.flow_table.setHorizontalHeaderLabels(["名称","类型","速率","PGID","状态","操作"])
        self.flow_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        list_l.addWidget(self.flow_table)

        refresh_row = QHBoxLayout()
        self.refresh_btn = QPushButton("刷新列表")
        self.refresh_btn.clicked.connect(self.on_refresh_clicked)
        refresh_row.addWidget(self.refresh_btn)
        list_l.addLayout(refresh_row)

        layout.addWidget(list_group)

        # status/log area
        self.status_text = QTextEdit()
        self.status_text.setReadOnly(True)
        self.status_text.setMaximumHeight(160)
        layout.addWidget(self.status_text)

        # initial state
        self._update_ui_state()
        # refresh initial list for view_port 0
        self.refresh_flow_list_for_port(int(self.view_port_combo.currentText()))

    # ----------------------- UI helpers -----------------------
    def _update_ui_state(self):
        # enable/disable fields based on checkboxes (simple)
        def toggle_enabled(cb, widgets):
            for w in widgets:
                w.setEnabled(cb.isChecked())
        toggle_enabled(self.rand_sip_cb, [self.sip_start_le, self.sip_end_le])
        toggle_enabled(self.rand_dip_cb, [self.dip_start_le, self.dip_end_le])
        toggle_enabled(self.rand_sport_cb, [self.sport_start_sb, self.sport_end_sb])
        toggle_enabled(self.rand_dport_cb, [self.dport_start_sb, self.dport_end_sb])
        toggle_enabled(self.rand_pkt_cb, [self.pkt_min_sb, self.pkt_max_sb])
        toggle_enabled(self.vlan_cb, [self.vlan_id_sb, self.vlan_prio_sb])

        # connect checkboxes to toggles
        self.rand_sip_cb.toggled.connect(lambda _: self._update_ui_state())
        self.rand_dip_cb.toggled.connect(lambda _: self._update_ui_state())
        self.rand_sport_cb.toggled.connect(lambda _: self._update_ui_state())
        self.rand_dport_cb.toggled.connect(lambda _: self._update_ui_state())
        self.rand_pkt_cb.toggled.connect(lambda _: self._update_ui_state())
        self.vlan_cb.toggled.connect(lambda _: self._update_ui_state())

    def append_status(self, msg: str, level: str = "信息"):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        self.status_text.append(f"[{ts}] [{level}] {msg}")
        # also forward to main log if possible
        if self.parent_window and hasattr(self.parent_window, "log_message"):
            try:
                self.parent_window.log_message(msg, level)
            except Exception:
                pass

    # ----------------------- parameter collection & validation -----------------------
    def _collect_params(self):
        """
        Collect parameters from UI controls and return (params_dict, error_message)
        If validation fails, params_dict is None and error_message contains the reason.
        """
        params = {}
        try:
            params['src_mac'] = self.src_mac_le.text().strip()
            params['dst_mac'] = self.dst_mac_le.text().strip()
            params['src_ip'] = self.src_ip_le.text().strip()
            params['dst_ip'] = self.dst_ip_le.text().strip()
            params['src_port'] = int(self.src_port_sb.value())
            params['dst_port'] = int(self.dst_port_sb.value())
            params['vlan_enabled'] = bool(self.vlan_cb.isChecked())
            params['vlan_id'] = int(self.vlan_id_sb.value())
            params['vlan_prio'] = int(self.vlan_prio_sb.value())
            params['pkt_size'] = int(self.pkt_size_sb.value())
            params['rate'] = float(self.rate_ds.value())

            # random flags and ranges
            params['random_src_ip'] = bool(self.rand_sip_cb.isChecked())
            params['sip_range_start'] = self.sip_start_le.text().strip()
            params['sip_range_end'] = self.sip_end_le.text().strip()

            params['random_dst_ip'] = bool(self.rand_dip_cb.isChecked())
            params['dip_range_start'] = self.dip_start_le.text().strip()
            params['dip_range_end'] = self.dip_end_le.text().strip()

            params['random_src_port'] = bool(self.rand_sport_cb.isChecked())
            params['sport_range_start'] = int(self.sport_start_sb.value())
            params['sport_range_end'] = int(self.sport_end_sb.value())

            params['random_dst_port'] = bool(self.rand_dport_cb.isChecked())
            params['dport_range_start'] = int(self.dport_start_sb.value())
            params['dport_range_end'] = int(self.dport_end_sb.value())

            params['random_pkt_size'] = bool(self.rand_pkt_cb.isChecked())
            params['pkt_size_min'] = int(self.pkt_min_sb.value())
            params['pkt_size_max'] = int(self.pkt_max_sb.value())

            # name/type
            params['name'] = self.flow_name_le.text().strip() or f"flow_{int(time.time())}"
            params['type'] = self.flow_type_cb.currentText().upper()

            # validate IPs and ranges
            if params['random_src_ip']:
                try:
                    ipaddress.IPv4Address(params['sip_range_start'])
                    ipaddress.IPv4Address(params['sip_range_end'])
                except Exception:
                    return None, "随机源IP段格式不正确"
            else:
                # validate single IP
                try:
                    ipaddress.IPv4Address(params['src_ip'])
                except Exception:
                    return None, "源IP格式不正确"

            if params['random_dst_ip']:
                try:
                    ipaddress.IPv4Address(params['dip_range_start'])
                    ipaddress.IPv4Address(params['dip_range_end'])
                except Exception:
                    return None, "随机目的IP段格式不正确"
            else:
                try:
                    ipaddress.IPv4Address(params['dst_ip'])
                except Exception:
                    return None, "目的IP格式不正确"

            # ports ranges
            if params['random_src_port']:
                if not (1 <= params['sport_range_start'] <= params['sport_range_end'] <= 65535):
                    return None, "源端口范围不正确"
            if params['random_dst_port']:
                if not (1 <= params['dport_range_start'] <= params['dport_range_end'] <= 65535):
                    return None, "目的端口范围不正确"

            # pkt size random
            if params['random_pkt_size']:
                if not (64 <= params['pkt_size_min'] <= params['pkt_size_max'] <= 9732):
                    return None, "随机包长范围不正确"

            # target ports parsing
            ports_text = self.target_ports_le.text().strip()
            if not ports_text:
                return None, "请填写目标端口"
            ports = []
            for p in ports_text.split(","):
                p = p.strip()
                if not p:
                    continue
                # allow ranges like 0-3
                if "-" in p:
                    try:
                        a,b = p.split("-",1)
                        a=int(a); b=int(b)
                        ports.extend(list(range(a, b+1)))
                    except Exception:
                        return None, f"端口范围格式错误: {p}"
                else:
                    try:
                        ports.append(int(p))
                    except Exception:
                        return None, f"端口格式错误: {p}"
            if not ports:
                return None, "未解析到有效目标端口"
            params['target_ports'] = sorted(list(set(ports)))

            return params, None
        except Exception as e:
            traceback.print_exc()
            return None, f"参数收集异常: {e}"

    # ----------------------- actions -----------------------
    def on_validate(self):
        params, err = self._collect_params()
        if err:
            QMessageBox.warning(self, "校验失败", err)
            self.append_status(err, "错误")
            return
        self.append_status("参数校验通过", "信息")
        QMessageBox.information(self, "校验通过", "参数看起来合法，可以继续下发或保存。")

    def on_save_local(self):
        params, err = self._collect_params()
        if err:
            QMessageBox.warning(self, "保存失败", err)
            self.append_status(err, "错误")
            return
        # save to controller local config for each port
        for port in params['target_ports']:
            cfg = {
                'name': params['name'],
                'type': params['type'],
                'params': params,
                'tx_ports': [port],
                'rx_ports': [port]
            }
            ok, msg = self.controller.add_flow_to_port(port, cfg)
            if ok:
                self.append_status(f"已保存本地流配置: 端口 {port} ({msg})", "信息")
            else:
                self.append_status(f"保存本地流失败: 端口 {port} ({msg})", "错误")
        # refresh list view port if affected
        try:
            self.refresh_flow_list_for_port(int(self.view_port_combo.currentText()))
        except Exception:
            pass

    def on_add_to_device(self):
        """
        Build flow using controller.create_flow_template and add to device (if connected).
        If not connected, fall back to saving locally.
        """
        params, err = self._collect_params()
        if err:
            QMessageBox.warning(self, "参数错误", err)
            self.append_status(err, "错误")
            return

        # create template from controller
        try:
            template = None
            if hasattr(self.controller, 'create_flow_template'):
                template = self.controller.create_flow_template(params['type'])
            if template is None:
                QMessageBox.warning(self, "创建失败", f"控制器不支持流类型 {params['type']} 的模板，已保存本地配置")
                self.on_save_local()
                return

            # build packet using template; template may internally call controller._create_vm_for_random
            pkt_obj = None
            try:
                pkt_obj = template['packet'](params)
            except Exception as e:
                # fallback: try to create VM via controller and re-run
                try:
                    vm = None
                    if hasattr(self.controller, '_create_vm_for_random'):
                        vm = self.controller._create_vm_for_random(params['type'], params)
                        params_with_vm = dict(params)
                        params_with_vm['vm'] = vm
                        pkt_obj = template['packet'](params_with_vm)
                    else:
                        raise
                except Exception as e2:
                    traceback.print_exc()
                    self.append_status(f"构建数据包失败: {e2}", "错误")
                    QMessageBox.warning(self, "构建失败", f"数据包构建失败: {e2}\n已保存本地配置")
                    self.on_save_local()
                    return

            # normalize to STLPktBuilder if TREX available
            pkt_builder = None
            if TREX_STL_AVAILABLE and isinstance(pkt_obj, STLPktBuilder):
                pkt_builder = pkt_obj
            else:
                if TREX_STL_AVAILABLE:
                    try:
                        pkt_builder = STLPktBuilder(pkt=pkt_obj)
                    except Exception as e:
                        traceback.print_exc()
                        pkt_builder = None
                else:
                    pkt_builder = None

            # If not connected to real T-Rex or packet builder missing, fallback to save local
            if not getattr(self.controller, 'is_connected', False) or not getattr(self.controller, 'client', None) or pkt_builder is None:
                self.append_status("未连接到 T-Rex 或无法构建 STLPktBuilder，已保存本地配置", "警告")
                self.on_save_local()
                return

            # add streams to each target port with unique PGID
            for port in params['target_ports']:
                try:
                    if port not in self.controller.flow_configs:
                        self.controller.flow_configs[port] = []

                    base_pgid = (port + 1) * 1000
                    flow_index = len(self.controller.flow_configs[port])
                    pgid = base_pgid + flow_index + 1

                    rate = float(params.get('rate', 50.0))
                    stream = STLStream(packet=pkt_builder, mode=STLTXCont(percentage=rate), flow_stats=STLFlowStats(pg_id=pgid))

                    # send to trex
                    self.controller.client.add_streams(stream, ports=[port])

                    # store in controller config
                    stored = {
                        'name': params['name'],
                        'type': params['type'],
                        'params': params,
                        'pgid': pgid,
                        'stream': stream,
                        'tx_ports': [port],
                        'rx_ports': [port],
                        'active': False
                    }
                    self.controller.flow_configs[port].append(stored)
                    self.append_status(f"已下发流到 T-Rex (port={port}, pgid={pgid})", "信息")
                except Exception as e:
                    traceback.print_exc()
                    self.append_status(f"端口 {port} 下发失败: {e}", "错误")
                    QMessageBox.warning(self, "下发失败", f"端口 {port} 下发失败: {e}")

            # refresh UI list
            try:
                self.refresh_flow_list_for_port(int(self.view_port_combo.currentText()))
            except Exception:
                pass

        except Exception as e:
            traceback.print_exc()
            self.append_status(f"下发异常: {e}", "错误")
            QMessageBox.critical(self, "异常", f"下发异常: {e}")

    # ----------------------- flow list & actions -----------------------
    def on_view_port_changed(self):
        try:
            port = int(self.view_port_combo.currentText())
        except Exception:
            port = 0
        self.refresh_flow_list_for_port(port)

    def on_refresh_clicked(self):
        try:
            port = int(self.view_port_combo.currentText())
        except Exception:
            port = 0
        self.refresh_flow_list_for_port(port)

    def refresh_flow_list_for_port(self, port: int):
        """Populate the flow_table with flows for the given port."""
        self.flow_table.setRowCount(0)
        #flows = self.controller.get_port_flows(port)
        flows = {}
        for i, f in enumerate(flows):
            row = self.flow_table.rowCount()
            self.flow_table.insertRow(row)
            self.flow_table.setItem(row, 0, QTableWidgetItem(f.get("name", f"flow_{i}")))
            self.flow_table.setItem(row, 1, QTableWidgetItem(f.get("type", "")))
            rate_text = str(f.get("params", {}).get("rate", f.get("rate", "")))
            self.flow_table.setItem(row, 2, QTableWidgetItem(rate_text))
            self.flow_table.setItem(row, 3, QTableWidgetItem(str(f.get("pgid", ""))))
            status_text = "活跃" if f.get("active") else "停止"
            status_item = QTableWidgetItem(status_text)
            if f.get("active"):
                status_item.setBackground(QColor(200,255,200))
            else:
                status_item.setBackground(QColor(255,200,200))
            self.flow_table.setItem(row, 4, status_item)

            # actions: Edit / Start / Stop / Delete
            action_widget = QWidget()
            h = QHBoxLayout()
            h.setContentsMargins(0,0,0,0)
            h.setSpacing(4)

            edit_btn = QPushButton("编辑"); edit_btn.setMaximumWidth(60)
            edit_btn.clicked.connect(partial(self.on_edit_flow, port, i))
            h.addWidget(edit_btn)

            start_btn = QPushButton("启动"); start_btn.setMaximumWidth(60)
            start_btn.clicked.connect(partial(self.on_start_flow, port, i))
            h.addWidget(start_btn)

            stop_btn = QPushButton("停止"); stop_btn.setMaximumWidth(60)
            stop_btn.clicked.connect(partial(self.on_stop_flow, port, i))
            h.addWidget(stop_btn)

            del_btn = QPushButton("删除"); del_btn.setMaximumWidth(60)
            del_btn.clicked.connect(partial(self.on_delete_flow, port, i))
            h.addWidget(del_btn)

            action_widget.setLayout(h)
            self.flow_table.setCellWidget(row, 5, action_widget)

    def on_edit_flow(self, port: int, index: int):
        """Load flow parameters into the form for editing."""
        try:
            flows = self.controller.get_port_flows(port)
            if index < 0 or index >= len(flows):
                self.append_status("所选流不存在", "错误")
                return
            f = flows[index]
            params = f.get('params', {})
            # populate fields (best-effort)
            self.flow_name_le.setText(f.get('name', ''))
            self.flow_type_cb.setCurrentText(f.get('type', 'UDP'))
            self.src_mac_le.setText(params.get('src_mac', self.src_mac_le.text()))
            self.dst_mac_le.setText(params.get('dst_mac', self.dst_mac_le.text()))
            self.src_ip_le.setText(params.get('src_ip', self.src_ip_le.text()))
            self.dst_ip_le.setText(params.get('dst_ip', self.dst_ip_le.text()))
            self.src_port_sb.setValue(int(params.get('src_port', self.src_port_sb.value())))
            self.dst_port_sb.setValue(int(params.get('dst_port', self.dst_port_sb.value())))
            self.vlan_cb.setChecked(bool(params.get('vlan_enabled', False)))
            self.vlan_id_sb.setValue(int(params.get('vlan_id', self.vlan_id_sb.value())))
            self.vlan_prio_sb.setValue(int(params.get('vlan_prio', self.vlan_prio_sb.value())))
            self.pkt_size_sb.setValue(int(params.get('pkt_size', self.pkt_size_sb.value())))
            self.rate_ds.setValue(float(params.get('rate', self.rate_ds.value())))

            # random flags
            self.rand_sip_cb.setChecked(bool(params.get('random_src_ip', False)))
            self.sip_start_le.setText(params.get('sip_range_start', self.sip_start_le.text()))
            self.sip_end_le.setText(params.get('sip_range_end', self.sip_end_le.text()))
            self.rand_dip_cb.setChecked(bool(params.get('random_dst_ip', False)))
            self.dip_start_le.setText(params.get('dip_range_start', self.dip_start_le.text()))
            self.dip_end_le.setText(params.get('dip_range_end', self.dip_end_le.text()))
            self.rand_sport_cb.setChecked(bool(params.get('random_src_port', False)))
            self.sport_start_sb.setValue(int(params.get('sport_range_start', self.sport_start_sb.value())))
            self.sport_end_sb.setValue(int(params.get('sport_range_end', self.sport_end_sb.value())))
            self.rand_dport_cb.setChecked(bool(params.get('random_dst_port', False)))
            self.dport_start_sb.setValue(int(params.get('dport_range_start', self.dport_start_sb.value())))
            self.dport_end_sb.setValue(int(params.get('dport_range_end', self.dport_end_sb.value())))
            self.rand_pkt_cb.setChecked(bool(params.get('random_pkt_size', False)))
            self.pkt_min_sb.setValue(int(params.get('pkt_size_min', self.pkt_min_sb.value())))
            self.pkt_max_sb.setValue(int(params.get('pkt_size_max', self.pkt_max_sb.value())))

            # set target ports to the flow's tx_ports
            txp = f.get('tx_ports', [])
            if txp:
                self.target_ports_le.setText(",".join(str(x) for x in txp))

            self.editing = (port, index)
            self.save_changes_btn.setEnabled(True)
            self.append_status(f"载入流进行编辑: 端口 {port} 索引 {index}", "信息")
        except Exception as e:
            traceback.print_exc()
            self.append_status(f"载入编辑失败: {e}", "错误")

    def on_save_changes(self):
        """Apply edits to an existing flow (update controller.flow_configs and re-add to device if connected)."""
        if not self.editing:
            QMessageBox.warning(self, "无编辑项", "当前没有正在编辑的流")
            return
        port, index = self.editing
        params, err = self._collect_params()
        if err:
            QMessageBox.warning(self, "参数错误", err)
            self.append_status(err, "错误")
            return
        try:
            flows = self.controller.get_port_flows(port)
            if index < 0 or index >= len(flows):
                QMessageBox.warning(self, "索引错误", "所编辑的流已不存在")
                self.append_status("所编辑的流已不存在", "错误")
                self.editing = None
                self.save_changes_btn.setEnabled(False)
                return

            # update local config
            flows[index]['name'] = params.get('name', flows[index].get('name'))
            flows[index]['params'] = params
            flows[index]['type'] = params.get('type', flows[index].get('type'))

            # if connected, re-add stream: remove all streams on port and re-add stored configs (controller handles re-adding in remove_flow_from_port)
            if getattr(self.controller, 'is_connected', False) and getattr(self.controller, 'client', None):
                # remove all streams and re-create from controller.flow_configs
                try:
                    # Use controller.clear_port_flows to remove streams and re-add from configs
                    # Implement re-add: remove all device streams, then for each config create stream and add_streams
                    try:
                        self.controller.client.remove_all_streams(ports=[port])
                    except Exception:
                        pass
                    # Rebuild streams for all flows on this port
                    for idx, fc in enumerate(self.controller.flow_configs.get(port, [])):
                        tpl = None
                        if hasattr(self.controller, 'create_flow_template'):
                            tpl = self.controller.create_flow_template(fc.get('type'))
                        if tpl:
                            try:
                                params = tpl['default_params'].copy()
                                params.update(fc.get('params', {}))
                                pkt_obj = tpl['packet'](params)
                            except Exception:
                                try:
                                    vm = self.controller._create_vm_for_random(fc.get('type'), fc.get('params', {}))
                                    p_with_vm = dict(fc.get('params', {})); p_with_vm['vm'] = vm
                                    pkt_obj = tpl['packet'](p_with_vm)
                                except Exception:
                                    pkt_obj = None
                            pkt_builder = None
                            if TREX_STL_AVAILABLE and isinstance(pkt_obj, STLPktBuilder):
                                pkt_builder = pkt_obj
                            elif TREX_STL_AVAILABLE and pkt_obj is not None:
                                try:
                                    pkt_builder = STLPktBuilder(pkt=pkt_obj)
                                except Exception:
                                    pkt_builder = None
                            if pkt_builder is None:
                                continue
                            # assign PGID (reuse existing if present)
                            pgid = fc.get('pgid') or ((port + 1) * 1000 + idx + 1)
                            stream = STLStream(packet=pkt_builder, mode=STLTXCont(percentage=fc.get('params', {}).get('rate', 50.0)), flow_stats=STLFlowStats(pg_id=pgid))
                            try:
                                self.controller.client.add_streams(stream, ports=[port])
                                fc['stream'] = stream
                                fc['pgid'] = pgid
                            except Exception:
                                pass
                except Exception as e:
                    traceback.print_exc()
                    self.append_status(f"重新下发流失败: {e}", "错误")

            self.append_status(f"已保存对端口{port} 流索引{index}的修改", "信息")
            self.editing = None
            self.save_changes_btn.setEnabled(False)
            # refresh list view
            self.refresh_flow_list_for_port(port)
        except Exception as e:
            traceback.print_exc()
            self.append_status(f"保存变更异常: {e}", "错误")

    def on_start_flow(self, port: int, index: int):
        try:
            ok, msg = self.controller.start_flow(port, index)
            if ok:
                self.append_status(f"已启动端口{port} 流{index}", "信息")
                # mark active and refresh
                try:
                    self.controller.flow_configs[port][index]['active'] = True
                except Exception:
                    pass
            else:
                self.append_status(f"启动失败: {msg}", "错误")
            self.refresh_flow_list_for_port(port)
        except Exception as e:
            traceback.print_exc()
            self.append_status(f"启动异常: {e}", "错误")

    def on_stop_flow(self, port: int, index: int):
        try:
            ok, msg = self.controller.stop_flow(port, index)
            if ok:
                self.append_status(f"已停止端口{port} 流{index}", "信息")
                try:
                    self.controller.flow_configs[port][index]['active'] = False
                except Exception:
                    pass
            else:
                self.append_status(f"停止失败: {msg}", "错误")
            self.refresh_flow_list_for_port(port)
        except Exception as e:
            traceback.print_exc()
            self.append_status(f"停止异常: {e}", "错误")

    def on_delete_flow(self, port: int, index: int):
        try:
            confirm = QMessageBox.question(self, "确认删除", f"确定要删除端口 {port} 的流索引 {index} 吗？", QMessageBox.Yes | QMessageBox.No)
            if confirm != QMessageBox.Yes:
                return
            ok, msg = self.controller.remove_flow_from_port(port, index)
            if ok:
                self.append_status(f"已删除端口{port} 流{index}: {msg}", "信息")
            else:
                self.append_status(f"删除失败: {msg}", "错误")
            # refresh
            self.refresh_flow_list_for_port(port)
        except Exception as e:
            traceback.print_exc()
            self.append_status(f"删除异常: {e}", "错误")

    def update_ui_connected(self, connected: bool):
        self.start_btn.setEnabled(connected)


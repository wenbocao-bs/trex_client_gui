# modules/traffic_tab.py
# 重构：通过预定义的 L2/L3/L4/TUNNEL 层预设构建报文，并且为每个占位字段支持模式：
# 固定值(fixed)、增量(inc)、递减(dec) 和 随机(random)。
#
# 主要点：
# - 在 composition 中为每层保存 template（含占位符）和 fields 配置。
# - UI 在选择 composition 条目时显示该层的 fields 编辑表格（可编辑模式与参数）。
# - 构建报文时根据各字段的 mode 与序号（flow_index）计算具体值并替换到 template 中得到具体表达式。
# - random 对 IP/数字分别做合理随机：IP 使用 ipaddress；数值使用 randint。
# - 新增 create_streams_from_composition 方法，基于 params['composition'] 生成 STLVM 指令、STLPktBuilder 与 STLStream，并扩展对 IPv6 的支持。
import random
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QPushButton,
    QGroupBox, QSpinBox, QLineEdit, QTextEdit, QListWidget,
    QListWidgetItem, QTableWidget, QTableWidgetItem, QMessageBox
)
from PyQt5.QtCore import Qt
import traceback
import ipaddress
import time
from functools import partial

# Optional T-Rex STL imports
try:
    from trex.stl.api import STLStream, STLPktBuilder, STLTXCont, STLFlowStats, STLVM
    TREX_STL_AVAILABLE = True
except Exception:
    STLStream = STLPktBuilder = STLTXCont = STLFlowStats = STLVM = None
    TREX_STL_AVAILABLE = False

# Optional scapy import for building/previewing composed packets
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except Exception:
    scapy = None
    SCAPY_AVAILABLE = False

# Layer presets (template contains placeholders like {src_ip}, {dst_port} etc.)
LAYER_PRESETS = {
    'L2': [
        {'id': 'eth', 'name': 'Ethernet', 'template': "Ether(dst='{dst_mac}', src='{src_mac}')"},
        {'id': 'vlan', 'name': '802.1Q VLAN', 'template': "Dot1Q(vlan={vlan_id}, prio={vlan_prio})"},
    ],
    'L3': [
        {'id': 'ipv4', 'name': 'IPv4', 'template': "IP(src='{src_ip}', dst='{dst_ip}')"},
        {'id': 'ipv6', 'name': 'IPv6', 'template': "IPv6(src='{src_ip}', dst='{dst_ip}')"},
    ],
    'L4': [
        {'id': 'udp', 'name': 'UDP', 'template': "UDP(sport={src_port}, dport={dst_port})"},
        {'id': 'tcp', 'name': 'TCP', 'template': "TCP(sport={src_port}, dport={dst_port})"},
    ],
    'TUNNEL': [
        {'id': 'vxlan', 'name': 'VXLAN (placeholder)', 'template': "Raw(b'VXLAN')"},
        {'id': 'gre', 'name': 'GRE (placeholder)', 'template': "GRE()"},
    ]
}

FIELD_MODES = ['fixed', 'inc', 'dec', 'random']

def extract_placeholders(template: str):
    import re
    return re.findall(r"\\{(\\w+)\\}", template)


class TrafficTab(QWidget):
    """
    支持通过预设层组合构建报文，并为每个占位字段提供模式配置（fixed/inc/dec/random）。
    composition is list of dict:
      {
        'family': 'L3',
        'preset_id': 'ipv4',
        'name': 'IPv4',
        'template': "IP(src='{src_ip}', dst='{dst_ip}')",
        'fields': {
            'src_ip': {'mode':'fixed','value':'1.2.3.4', 'start':'16.0.0.1','end':'16.0.0.1','step':1},
        }
      }
    """
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.parent_window = parent
        self.composition = []
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        base_row = QHBoxLayout()
        base_row.addWidget(QLabel("流名称:"))
        self.flow_name_le = QLineEdit(f"flow_{int(time.time())}")
        base_row.addWidget(self.flow_name_le)
        base_row.addWidget(QLabel("源MAC:"))
        self.src_mac_le = QLineEdit("00:03:00:01:40:01")
        base_row.addWidget(self.src_mac_le)
        base_row.addWidget(QLabel("目的MAC:"))
        self.dst_mac_le = QLineEdit("00:02:00:03:04:02")
        base_row.addWidget(self.dst_mac_le)
        layout.addLayout(base_row)

        ip_row = QHBoxLayout()
        ip_row.addWidget(QLabel("源IP:"))
        self.src_ip_le = QLineEdit("16.0.0.1")
        ip_row.addWidget(self.src_ip_le)
        ip_row.addWidget(QLabel("目的IP:"))
        self.dst_ip_le = QLineEdit("48.0.0.1")
        ip_row.addWidget(self.dst_ip_le)
        ip_row.addWidget(QLabel("源端口:"))
        self.src_port_sb = QSpinBox(); self.src_port_sb.setRange(1,65535); self.src_port_sb.setValue(1025)
        ip_row.addWidget(self.src_port_sb)
        ip_row.addWidget(QLabel("目的端口:"))
        self.dst_port_sb = QSpinBox(); self.dst_port_sb.setRange(1,65535); self.dst_port_sb.setValue(80)
        ip_row.addWidget(self.dst_port_sb)
        layout.addLayout(ip_row)

        # Preset selection
        presets_box = QGroupBox("层预设（选择后点击 Add Layer）")
        pbl = QVBoxLayout(); presets_box.setLayout(pbl)
        sel_row = QHBoxLayout()
        sel_row.addWidget(QLabel("层类型:"))
        self.family_cb = QComboBox()
        self.family_cb.addItems(['L2','L3','L4','TUNNEL'])
        self.family_cb.currentTextChanged.connect(self._on_family_changed)
        sel_row.addWidget(self.family_cb)
        sel_row.addWidget(QLabel("预设:"))
        self.preset_cb = QComboBox()
        sel_row.addWidget(self.preset_cb)
        self.add_layer_btn = QPushButton("Add Layer"); self.add_layer_btn.clicked.connect(self.on_add_layer)
        sel_row.addWidget(self.add_layer_btn)
        pbl.addLayout(sel_row)

        # Composition list and field editor
        comp_row = QHBoxLayout()
        left_v = QVBoxLayout()
        left_v.addWidget(QLabel("Composition (按顺序)"))
        self.composition_list = QListWidget()
        self.composition_list.currentRowChanged.connect(self.on_composition_selection_changed)
        left_v.addWidget(self.composition_list)
        btn_row = QHBoxLayout()
        self.up_btn = QPushButton("Up"); self.up_btn.clicked.connect(self.on_move_up)
        self.down_btn = QPushButton("Down"); self.down_btn.clicked.connect(self.on_move_down)
        self.remove_btn = QPushButton("Remove"); self.remove_btn.clicked.connect(self.on_remove_layer)
        btn_row.addWidget(self.up_btn); btn_row.addWidget(self.down_btn); btn_row.addWidget(self.remove_btn)
        left_v.addLayout(btn_row)
        comp_row.addLayout(left_v)

        right_v = QVBoxLayout()
        right_v.addWidget(QLabel("Selected Layer Fields (mode: fixed/inc/dec/random)"))
        # Table: Field | Mode | Value/Start | End | Step
        self.field_table = QTableWidget(0,5)
        self.field_table.setHorizontalHeaderLabels(['Field','Mode','Value/Start','End','Step'])
        self.field_table.horizontalHeader().setStretchLastSection(True)
        right_v.addWidget(self.field_table)
        # Apply changes button
        self.apply_fields_btn = QPushButton("Apply Field Changes"); self.apply_fields_btn.clicked.connect(self.on_apply_field_changes)
        right_v.addWidget(self.apply_fields_btn)
        comp_row.addLayout(right_v)

        pbl.addLayout(comp_row)
        pbl.addWidget(QLabel("组合报文预览:"))
        self.preview_te = QTextEdit(); self.preview_te.setReadOnly(True); self.preview_te.setMaximumHeight(140)
        pbl.addWidget(self.preview_te)

        layout.addWidget(presets_box)

        action_row = QHBoxLayout()
        action_row.addWidget(QLabel("目标端口 (逗号/范围):"))
        self.target_ports_le = QLineEdit("0")
        action_row.addWidget(self.target_ports_le)
        self.save_local_btn = QPushButton("仅保存本地配置"); self.save_local_btn.clicked.connect(self.on_save_local)
        action_row.addWidget(self.save_local_btn)
        self.add_to_device_btn = QPushButton("下发到 T-Rex 并保存"); self.add_to_device_btn.clicked.connect(self.on_add_to_device)
        action_row.addWidget(self.add_to_device_btn)
        layout.addLayout(action_row)

        self.status_te = QTextEdit(); self.status_te.setReadOnly(True); self.status_te.setMaximumHeight(140)
        layout.addWidget(self.status_te)

        # initialize presets combobox
        self._on_family_changed(self.family_cb.currentText())

    # ---------------- UI helpers ----------------
    def append_status(self, msg, level="信息"):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        self.status_te.append(f"[{ts}] [{level}] {msg}")

    def _on_family_changed(self, family):
        self.preset_cb.clear()
        for p in LAYER_PRESETS.get(family, []):
            self.preset_cb.addItem(p['name'], p)

    # ---------------- Composition operations ----------------
    def on_add_layer(self):
        preset = self.preset_cb.currentData()
        if not preset:
            QMessageBox.warning(self, "错误", "未选择预设")
            return
        template = preset['template']
        # initial fields extracted from template placeholders
        placeholders = extract_placeholders(template)
        fields = {}
        # default values taken from UI base fields where appropriate
        defaults = {
            'src_mac': self.src_mac_le.text().strip(),
            'dst_mac': self.dst_mac_le.text().strip(),
            'src_ip': self.src_ip_le.text().strip(),
            'dst_ip': self.dst_ip_le.text().strip(),
            'src_port': int(self.src_port_sb.value()),
            'dst_port': int(self.dst_port_sb.value()),
            'vlan_id': 100,
            'vlan_prio': 0
        }
        for ph in placeholders:
            # set default end to same as start/value to provide a sensible default
            fld = {'mode':'fixed', 'value':defaults.get(ph, ''), 'start':defaults.get(ph, ''), 'end':defaults.get(ph, ''), 'step':1}
            fields[ph] = fld
        layer = {
            'family': self.family_cb.currentText(),
            'preset_id': preset['id'],
            'name': preset['name'],
            'template': template,
            'fields': fields
        }
        self.composition.append(layer)
        self.composition_list.addItem(QListWidgetItem(f"{layer['family']} - {layer['name']}"))
        self.update_preview()
        self.append_status(f"Added layer {layer['family']} {layer['name']}")

    def on_move_up(self):
        i = self.composition_list.currentRow()
        if i > 0:
            self.composition[i-1], self.composition[i] = self.composition[i], self.composition[i-1]
            item = self.composition_list.takeItem(i)
            self.composition_list.insertItem(i-1, item)
            self.composition_list.setCurrentRow(i-1)
            self.update_preview()

    def on_move_down(self):
        i = self.composition_list.currentRow()
        if i >= 0 and i < len(self.composition)-1:
            self.composition[i+1], self.composition[i] = self.composition[i], self.composition[i+1]
            item = self.composition_list.takeItem(i)
            self.composition_list.insertItem(i+1, item)
            self.composition_list.setCurrentRow(i+1)
            self.update_preview()

    def on_remove_layer(self):
        i = self.composition_list.currentRow()
        if i >= 0:
            self.composition.pop(i)
            self.composition_list.takeItem(i)
            self.field_table.setRowCount(0)
            self.update_preview()

    def update_preview(self):
        if not self.composition:
            self.preview_te.setPlainText("<empty>")
            return
        parts = []
        for layer in self.composition:
            # create a shallow preview: replace placeholders using current 'value' if fixed, else show placeholder
            tpl = layer.get('template', '')
            vals = {}
            for k, v in layer.get('fields', {}).items():
                if v.get('mode') == 'fixed':
                    vals[k] = v.get('value', '')
                else:
                    vals[k] = "{" + k + "}"
            try:
                part = tpl.format(**vals)
            except Exception:
                part = tpl
            parts.append(part)
        expr = " / ".join(parts)
        self.preview_te.setPlainText(expr)

    def on_composition_selection_changed(self, idx):
        self.field_table.setRowCount(0)
        if idx < 0 or idx >= len(self.composition):
            return
        layer = self.composition[idx]
        fields = layer.get('fields', {})
        self.field_table.setRowCount(len(fields))
        for r, (fname, fcfg) in enumerate(fields.items()):
            # Field name
            it = QTableWidgetItem(fname)
            it.setFlags(Qt.ItemIsEnabled)
            self.field_table.setItem(r, 0, it)
            # Mode combo
            mode_cb = QComboBox()
            mode_cb.addItems(FIELD_MODES)
            mode_cb.setCurrentText(fcfg.get('mode', 'fixed'))
            self.field_table.setCellWidget(r, 1, mode_cb)
            # Value/Start
            val_it = QTableWidgetItem(str(fcfg.get('value', '')))
            self.field_table.setItem(r, 2, val_it)
            # End
            end_it = QTableWidgetItem(str(fcfg.get('end', '')))
            self.field_table.setItem(r, 3, end_it)
            # Step
            step_it = QTableWidgetItem(str(fcfg.get('step', 1)))
            self.field_table.setItem(r, 4, step_it)

    def on_apply_field_changes(self):
        idx = self.composition_list.currentRow()
        if idx < 0 or idx >= len(self.composition):
            return
        layer = self.composition[idx]
        new_fields = {}
        for r in range(self.field_table.rowCount()):
            fname = self.field_table.item(r,0).text()
            mode_cb = self.field_table.cellWidget(r,1)
            mode = mode_cb.currentText() if mode_cb else 'fixed'
            val = self.field_table.item(r,2).text() if self.field_table.item(r,2) else ''
            end = self.field_table.item(r,3).text() if self.field_table.item(r,3) else ''
            step_s = self.field_table.item(r,4).text() if self.field_table.item(r,4) else '1'
            try:
                step = int(step_s)
            except Exception:
                step = 1
            # ensure start/end defaults remain sensible: if start empty use value; if end empty use start/value
            start_val = val if val else ''
            end_val = end if end else start_val
            new_fields[fname] = {'mode': mode, 'value': val, 'start': start_val, 'end': end_val, 'step': step}
        layer['fields'] = new_fields
        self.composition[idx] = layer
        self.update_preview()
        self.append_status(f"Updated fields for layer {layer.get('name')}")

    # ---------------- Parameter collection ----------------
    def _collect_params(self):
        try:
            params = {}
            params['name'] = self.flow_name_le.text().strip() or f"flow_{int(time.time())}"
            params['src_mac'] = self.src_mac_le.text().strip()
            params['dst_mac'] = self.dst_mac_le.text().strip()
            params['src_ip'] = self.src_ip_le.text().strip()
            params['dst_ip'] = self.dst_ip_le.text().strip()
            params['src_port'] = int(self.src_port_sb.value())
            params['dst_port'] = int(self.dst_port_sb.value())
            ports_text = self.target_ports_le.text().strip()
            if not ports_text:
                return None, "请填写目标端口"
            ports = []
            for p in ports_text.split(","):
                p = p.strip()
                if not p:
                    continue
                if "-" in p:
                    try:
                        a,b = p.split("-",1)
                        a = int(a); b = int(b)
                        ports.extend(range(a, b+1))
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
            params['composition'] = [dict(x) for x in self.composition]
            return params, None
        except Exception as e:
            traceback.print_exc()
            return None, f"参数收集异常: {e}"

    # ---------------- Field value resolution ----------------
    def _is_ip(self, s: str):
        try:
            if ':' in str(s):
                ipaddress.IPv6Address(str(s))
            else:
                ipaddress.IPv4Address(str(s))
            return True
        except Exception:
            return False

    def _ip_to_int(self, ip_s):
        if ':' in str(ip_s):
            return int(ipaddress.IPv6Address(ip_s))
        return int(ipaddress.IPv4Address(ip_s))

    def _int_to_ip(self, i, v6=False):
        if v6:
            return str(ipaddress.IPv6Address(i))
        return str(ipaddress.IPv4Address(i))

    def resolve_field_value(self, field_cfg: dict, seq_index: int):
        """
        field_cfg: {'mode','value','start','end','step'}
        seq_index: zero-based index used for inc/dec
        """
        mode = field_cfg.get('mode', 'fixed')
        if mode == 'fixed':
            return field_cfg.get('value', '')
        if mode == 'random':
            start = field_cfg.get('start', '')
            end = field_cfg.get('end', '')
            # Try IP range (v4 or v6)
            try:
                if ':' in str(start) or ':' in str(end):
                    s = self._ip_to_int(start); e = self._ip_to_int(end)
                    if s > e:
                        s, e = e, s
                    val = random.randint(s, e)
                    return self._int_to_ip(val, v6=True)
                else:
                    s = self._ip_to_int(start); e = self._ip_to_int(end)
                    if s > e:
                        s, e = e, s
                    val = random.randint(s, e)
                    return self._int_to_ip(val)
            except Exception:
                pass
            # numeric fallback
            try:
                s = int(start); e = int(end)
                if s > e:
                    s, e = e, s
                return str(random.randint(s, e))
            except Exception:
                # fallback to choose from comma separated list if provided
                opts = (str(start) + ',' + str(end)).split(',')
                opts = [x.strip() for x in opts if x.strip()]
                if opts:
                    return random.choice(opts)
                return field_cfg.get('value', '')
        if mode in ('inc', 'dec'):
            # base is start (or value), step default field_cfg.step
            try:
                base_s = field_cfg.get('start', field_cfg.get('value', ''))
                step = int(field_cfg.get('step', 1))
                # IP sequence (supports v4/v6)
                if ':' in str(base_s):
                    base = self._ip_to_int(base_s)
                    if mode == 'inc':
                        val = base + seq_index * step
                    else:
                        val = base - seq_index * step
                    return self._int_to_ip(val, v6=True)
                else:
                    base = int(base_s)
                    if mode == 'inc':
                        val = base + seq_index * step
                    else:
                        val = base - seq_index * step
                    return str(val)
            except Exception:
                return field_cfg.get('value', '')
        # fallback
        return field_cfg.get('value', '')

    # ---------------- Build packet from composition ----------------
    def build_packet_from_composition_for_index(self, composition, seq_index):
        """
        Build concrete expression for one sequence index (used when adding streams).
        Returns composed expr (string) and, if possible, scapy.Packet object.
        """
        parts = []
        for layer in composition:
            tpl = layer.get('template', '')
            fields = layer.get('fields', {})
            subs = {}
            for k, cfg in fields.items():
                subs[k] = self.resolve_field_value(cfg, seq_index)
            try:
                part = tpl.format(**subs)
            except Exception:
                part = tpl
            parts.append(part)
        expr = " / ".join(parts)
        if SCAPY_AVAILABLE:
            try:
                ctx = {
                    'Ether': scapy.Ether,
                    'Dot1Q': getattr(scapy, 'Dot1Q', None),
                    'IP': scapy.IP,
                    'IPv6': scapy.IPv6,
                    'UDP': scapy.UDP,
                    'TCP': scapy.TCP,
                    'GRE': getattr(scapy, 'GRE', None),
                    'Raw': scapy.Raw,
                }
                pkt = eval(expr, {}, ctx)
                return expr, pkt
            except Exception:
                traceback.print_exc()
                return expr, None
        else:
            return expr, None

    # ---------------- Create streams from composition (trex VM generation supporting IPv6) ----------------
    def create_streams_from_composition(self, params):
        """
        根据 params['composition'] 动态生成 STLVM 指令并构建 STLPktBuilder/STLStream 列表。
        返回 (streams, err)：
          - 当 trex 可用且 streams 生成成功： ( [STLStream, ...], None )
          - 当 trex 不可用或失败： ( [ (size, pkt_template, vm_desc), ... ], "trex not available or error" )
        支持 IPv4/IPv6：对 IP 字段会判断是否含 ':' 来决定 IPv6 处理。
        """
        import traceback
        try:
            trex_ok = TREX_STL_AVAILABLE
        except Exception:
            trex_ok = False

        try:
            scapy_ok = SCAPY_AVAILABLE
        except Exception:
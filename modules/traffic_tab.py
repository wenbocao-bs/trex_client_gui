# modules/traffic_tab.py
# 重构：通过预定义的 L2/L3/L4/TUNNEL 层预设构建报文，并且为每个占位字段支持模式：
# fixed / inc / dec / random。并且基于 params['composition'] 生成 TREX VM（支持 IPv4/IPv6）
# 并把 create_streams_from_composition 集成到下发逻辑（on_add_to_device）。
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
        {'id': 'vxlan', 'name': 'VXLAN (placeholder)', 'template': "VXLAN(vni={vni})"},
        {'id': 'gre', 'name': 'GRE (placeholder)', 'template': "GRE()"},
    ]
}

FIELD_MODES = ['fixed', 'inc', 'dec', 'random']

def extract_placeholders(template: str):
    import re
    return re.findall(r"\{(\w+)\}", template)


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
                    'VXLAN': getattr(scapy, 'VXLAN', None),
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
        import traceback, ipaddress

        trex_ok = TREX_STL_AVAILABLE
        scapy_ok = SCAPY_AVAILABLE

        comp = params.get('composition', [])
        rate = float(params.get('rate', 10.0))
        vlan_enabled = bool(params.get('vlan_enabled', False))
        flow_type = (params.get('flow_type') or '').upper()

        # helper: map field name to TREX pkt_offset
        def pkt_field_for(fname, l4_proto='UDP', is_ipv6=False):
            f = fname.lower()
            # ip fields
            if 'src_ip' == f or f.endswith('_src_ip') or f in ('srcip','src_ip'):
                return 'IPv6.src' if is_ipv6 else 'IP.src'
            if 'dst_ip' == f or f.endswith('_dst_ip') or f in ('dstip','dst_ip','dst_ip'):
                return 'IPv6.dst' if is_ipv6 else 'IP.dst'
            # port fields
            if 'src_port' == f or f == 'sport' or f.endswith('src_port'):
                return f"{l4_proto}.sport"
            if 'dst_port' == f or f == 'dport' or f.endswith('dst_port'):
                return f"{l4_proto}.dport"
            # mac
            if 'src_mac' == f or f == 'smac':
                return 'ETH.src'
            if 'dst_mac' == f or f == 'dmac':
                return 'ETH.dst'
            if 'vlan' in f or 'vlan_id' == f:
                return 'Dot1Q.vlan'
            # fallback
            if 'ip' in f:
                return 'IPv6.src' if is_ipv6 else 'IP.src'
            if 'port' in f:
                return f"{l4_proto}.sport"
            return None

        # Build a minimal scapy packet from composition for a given size (best-effort)
        def build_base_packet_for_size(sz=None):
            if scapy_ok:
                # build layers based on composition fixed values
                eth_layer = None
                l3_layer = None
                l4_layer = None
                payload = b''
                for layer in comp:
                    tpl = layer.get('template','')
                    fields = layer.get('fields', {})
                    # simple heuristics
                    if 'Ether' in tpl or layer.get('preset_id','').lower() == 'eth':
                        src = fields.get('src_mac',{}).get('value') or params.get('src_mac')
                        dst = fields.get('dst_mac',{}).get('value') or params.get('dst_mac')
                        eth_layer = scapy.Ether(src=src, dst=dst)
                    if 'IPv6' in tpl or layer.get('preset_id','').lower() == 'ipv6':
                        src = fields.get('src_ip',{}).get('value') or params.get('src_ip')
                        dst = fields.get('dst_ip',{}).get('value') or params.get('dst_ip')
                        l3_layer = scapy.IPv6(src=src, dst=dst)
                    if 'IP(' in tpl or layer.get('preset_id','').lower() == 'ipv4':
                        src = fields.get('src_ip',{}).get('value') or params.get('src_ip')
                        dst = fields.get('dst_ip',{}).get('value') or params.get('dst_ip')
                        l3_layer = scapy.IP(src=src, dst=dst)
                    if 'UDP' in tpl or layer.get('preset_id','').lower() == 'udp':
                        sport = int(fields.get('src_port',{}).get('value') or params.get('src_port') or 1025)
                        dport = int(fields.get('dst_port',{}).get('value') or params.get('dst_port') or 80)
                        l4_layer = scapy.UDP(sport=sport, dport=dport)
                    if 'TCP' in tpl or layer.get('preset_id','').lower() == 'tcp':
                        sport = int(fields.get('src_port',{}).get('value') or params.get('src_port') or 1025)
                        dport = int(fields.get('dst_port',{}).get('value') or params.get('dst_port') or 80)
                        l4_layer = scapy.TCP(sport=sport, dport=dport)
                # default minimal
                if eth_layer is None:
                    eth_layer = scapy.Ether(src=params.get('src_mac','00:03:00:01:40:01'),
                                            dst=params.get('dst_mac','00:02:00:03:04:02'))
                if l3_layer is None:
                    # fallback to IPv4 with base params
                    l3_layer = scapy.IP(src=params.get('src_ip','16.0.0.1'),
                                        dst=params.get('dst_ip','48.0.0.1'))
                if l4_layer is None:
                    l4_layer = scapy.UDP(sport=params.get('src_port',1025), dport=params.get('dst_port',80))
                pkt = eth_layer / l3_layer / l4_layer
                hdr_len = len(bytes(pkt))
                if sz and sz > hdr_len:
                    pkt = pkt / scapy.Raw(load=b'X' * (sz - hdr_len))
                return pkt
            else:
                # fallback raw bytes
                return b'\x00' * (sz or 64)

        # Prepare VM (trex) or descriptive vm_desc
        vm = None
        vm_desc = {'vars': [], 'writes': []}
        if trex_ok:
            vm = STLVM()
        var_counter = 0

        # determine l4 proto guess from composition or params
        l4_guess = (params.get('flow_type') or '').upper()
        if not l4_guess:
            for layer in comp:
                if layer.get('preset_id','').lower() == 'tcp':
                    l4_guess = 'TCP'; break
                if layer.get('preset_id','').lower() == 'udp':
                    l4_guess = 'UDP'; break
        if not l4_guess:
            l4_guess = 'UDP'

        # iterate composition and create VM entries
        for li, layer in enumerate(comp):
            fields = layer.get('fields', {})
            for fname, fcfg in fields.items():
                mode = fcfg.get('mode','fixed')
                start = fcfg.get('start', fcfg.get('value',''))
                end = fcfg.get('end', start)
                step = int(fcfg.get('step', 1) or 1)
                # decide if IP v6
                is_ipv6 = False
                if isinstance(start,str) and ':' in start:
                    is_ipv6 = True
                if isinstance(end,str) and ':' in end:
                    is_ipv6 = True
                pkt_field = pkt_field_for(fname, l4_proto=l4_guess, is_ipv6=is_ipv6)
                if not pkt_field:
                    continue
                var_name = f"vm_{li}_{var_counter}_{fname}"
                var_counter += 1

                # IP handling
                if 'ip' in fname.lower():
                    try:
                        if is_ipv6:
                            s_int = int(ipaddress.IPv6Address(start))
                            e_int = int(ipaddress.IPv6Address(end))
                        else:
                            s_int = int(ipaddress.IPv4Address(start))
                            e_int = int(ipaddress.IPv4Address(end))
                    except Exception:
                        s_int = e_int = None
                    if trex_ok and s_int is not None and e_int is not None:
                        op = 'inc'
                        if mode == 'random':
                            op = 'rand'
                        if mode == 'dec':
                            op = 'dec'
                        try:
                            vm.var(name=var_name, min_value=s_int, max_value=e_int, size=16 if is_ipv6 else 4, op=op)
                            vm.write(fv_name=var_name, pkt_offset=pkt_field)
                        except Exception:
                            # version differences: try alternative param names
                            try:
                                vm.var(var_name, s_int, e_int, 16 if is_ipv6 else 4, op)
                                vm.write(fv_name=var_name, pkt_offset=pkt_field)
                            except Exception:
                                vm_desc['vars'].append(('ip', var_name, start, end, mode, step, pkt_field))
                                vm_desc['writes'].append((var_name, pkt_field))
                    else:
                        vm_desc['vars'].append(('ip', var_name, start, end, mode, step))
                        vm_desc['writes'].append((var_name, pkt_field))

                # port handling
                elif 'port' in fname.lower():
                    try:
                        s_n = int(start); e_n = int(end)
                    except Exception:
                        s_n = e_n = None
                    if trex_ok and s_n is not None and e_n is not None:
                        op = 'inc'
                        if mode == 'random':
                            op = 'rand'
                        if mode == 'dec':
                            op = 'dec'
                        try:
                            vm.var(name=var_name, min_value=s_n, max_value=e_n, size=2, op=op)
                            vm.write(fv_name=var_name, pkt_offset=pkt_field)
                        except Exception:
                            vm_desc['vars'].append(('port', var_name, start, end, mode, step))
                            vm_desc['writes'].append((var_name, pkt_field))
                    else:
                        vm_desc['vars'].append(('port', var_name, start, end, mode, step))
                        vm_desc['writes'].append((var_name, pkt_field))

                # mac handling
                elif 'mac' in fname.lower():
                    # TREX mac ranged vars are uncommon; handle fixed write or descriptive
                    val = fcfg.get('value','')
                    if trex_ok and val:
                        try:
                            # try treat MAC as integer
                            mac_int = int(val.replace(':','').replace('-',''), 16)
                            vm.var(name=var_name, min_value=mac_int, max_value=mac_int, size=6, op='inc')
                            vm.write(fv_name=var_name, pkt_offset=pkt_field)
                        except Exception:
                            vm_desc['vars'].append(('mac', var_name, val, val, 'fixed', 1))
                            vm_desc['writes'].append((var_name, pkt_field))
                    else:
                        vm_desc['vars'].append(('mac', var_name, val, val, 'fixed', 1))
                        vm_desc['writes'].append((var_name, pkt_field))
                else:
                    vm_desc['vars'].append(('other', var_name, start, end, mode, step))
                    vm_desc['writes'].append((var_name, pkt_field))

        # request checksum fix if trex available
        if trex_ok:
            try:
                vm.fix_chksum()
            except Exception:
                try:
                    vm.fix_ipv4()
                except Exception:
                    pass

        # packet size handling: produce 1..N sizes
        sizes = []
        p0 = params.get('pkt_size_start', None)
        p1 = params.get('pkt_size_end', None)
        pst = int(params.get('pkt_size_step', 1) or 1)
        if p0 is not None and p1 is not None:
            try:
                a = int(p0); b = int(p1)
                if a <= b:
                    sizes = list(range(a, b+1, pst))
                else:
                    sizes = list(range(b, a+1, pst))
            except Exception:
                sizes = []
        if not sizes:
            sizes = [None]

        streams = []
        infos = []

        for sz in sizes:
            pkt_template = build_base_packet_for_size(sz)
            pkt_bytes = None
            if SCAPY_AVAILABLE and scapy is not None and pkt_template is not None:
                # detect scapy packet by duck-typing: has 'build' or '__bytes__' or 'summary'
                is_scapy_pkt = hasattr(pkt_template, 'summary') or hasattr(pkt_template, 'build') or hasattr(pkt_template, '__bytes__')
            else:
                is_scapy_pkt = False

            if not is_scapy_pkt:
                if isinstance(pkt_template, bytes):
                    pkt_bytes = pkt_template
                else:
                    # fallback raw bytes
                    pkt_bytes = b'\x00' * (sz or 64)

            if trex_ok:
                try:
                    # prefer passing scapy.Packet (pkt_template) directly to STLPktBuilder when possible
                    if is_scapy_pkt:
                        try:
                            pkt_builder = STLPktBuilder(pkt=pkt_template, vm=vm)
                        except Exception:
                            # some STLPktBuilder versions may not accept scapy.Packet directly -> try bytes
                            try:
                                pkt_builder = STLPktBuilder(pkt=bytes(pkt_template), vm=vm)
                            except Exception:
                                # final fallback: create raw bytes packet
                                pkt_builder = STLPktBuilder(pkt=bytes(pkt_template) if hasattr(pkt_template, '__bytes__') else (pkt_bytes or b'\x00'*(sz or 64)), vm=vm)
                    else:
                        pkt_builder = STLPktBuilder(pkt=pkt_bytes or b'\x00'*(sz or 64), vm=vm)
                    stream = STLStream(packet=pkt_builder, mode=STLTXCont(percentage=rate))
                    streams.append(stream)
                except Exception:
                    traceback.print_exc()
                    infos.append((sz, pkt_template, vm_desc))
            else:
                infos.append((sz, pkt_template, vm_desc))

        if trex_ok and streams:
            return streams, None
        else:
            return infos, "trex not available or streams generation failed"

    # ---------------- Actions ----------------
    def on_save_local(self):
        params, err = self._collect_params()
        if err:
            QMessageBox.warning(self, "保存失败", err)
            self.append_status(err, "错误")
            return
        for port in params['target_ports']:
            cfg = {
                'name': params['name'],
                'type': 'COMPOSED',
                'params': params,
                'tx_ports': [port],
                'rx_ports': [port]
            }
            try:
                ok, msg = self.controller.add_flow_to_port(port, cfg)
                if ok:
                    self.append_status(f"已保存本地流配置: 端口 {port} ({msg})", "信息")
                else:
                    self.append_status(f"保存本地流失败: 端口 {port} ({msg})", "错误")
            except Exception as e:
                traceback.print_exc()
                self.append_status(f"调用控制器保存本地配置失败: {e}", "错误")

    def on_add_to_device(self):
        params, err = self._collect_params()
        if err:
            QMessageBox.warning(self, "参数错误", err)
            self.append_status(err, "错误")
            return

        # For each target port, use current flow_configs length as sequence base
        for port in params['target_ports']:
            try:
                if port not in self.controller.flow_configs:
                    self.controller.flow_configs[port] = []
                flow_index = len(self.controller.flow_configs[port])
                # Build streams from composition (may return STLPktBuilder-wrapped streams or infos)
                streams_or_infos, err2 = self.create_streams_from_composition(params)
                if err2 is not None:
                    # fallback: save local config (and show vm_desc)
                    self.append_status("无法直接下发到 T-Rex（或生成 streams 失败），已保存本地配置。详情见 vm_desc。", "警告")
                    # Save local config for port
                    cfg = {
                        'name': params['name'],
                        'type': 'COMPOSED',
                        'params': params,
                        'tx_ports': [port],
                        'rx_ports': [port],
                        'vm_desc': streams_or_infos
                    }
                    ok, msg = self.controller.add_flow_to_port(port, cfg)
                    if ok:
                        self.append_status(f"已保存本地流配置(回退): 端口 {port} ({msg})", "信息")
                    else:
                        self.append_status(f"保存本地流失败(回退): 端口 {port} ({msg})", "错误")
                    continue

                # streams_or_infos is list of STLStream
                for s_i, stream in enumerate(streams_or_infos):
                    # create pgid deterministic from port + index
                    base_pgid = (port + 1) * 1000
                    pgid = base_pgid + flow_index + s_i + 1
                    # attach flow stats with pg_id if possible
                    try:
                        # wrap stream with updated flow_stats
                        if hasattr(stream, 'flow_stats') and stream.flow_stats is not None:
                            stream.flow_stats.pg_id = pgid
                        else:
                            # if stream has constructor-based flow_stats, re-create minimal wrapper
                            pass
                    except Exception:
                        pass
                    # attempt to add streams to trex client
                    if getattr(self.controller, 'is_connected', False) and getattr(self.controller, 'client', None) is not None:
                        try:
                            self.controller.client.add_streams(stream, ports=[port])
                        except Exception:
                            # some clients expect list
                            try:
                                self.controller.client.add_streams([stream], ports=[port])
                            except Exception:
                                traceback.print_exc()
                                # fallback to saving local
                                self.append_status("向 T-Rex 下发流时出错，已保存本地配置", "错误")
                                self.on_save_local()
                                continue
                    # store metadata in controller.flow_configs
                    stored = {
                        'name': params['name'],
                        'type': 'COMPOSED',
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

    def refresh_flow_list_for_port(self, port: int):
        # placeholder for compatibility
        pass

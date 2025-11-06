# modules/traffic_tab.py
# 重构：通过预定义的 L2/L3/L4/TUNNEL 层预设构建报文，并且为每个占位字段支持模式：
# fixed / inc / dec / random。并且基于 params['composition'] 生成 TREX VM（支持 IPv4/IPv6）
# 并把 create_streams_from_composition 集成到下发逻辑（on_add_to_device）。
import random
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QPushButton,
    QGroupBox, QSpinBox, QLineEdit, QTextEdit, QListWidget,
    QListWidgetItem, QTableWidget, QTableWidgetItem, QMessageBox, QCheckBox
)
from PyQt5.QtCore import Qt
import traceback
import ipaddress
import time
import copy
from modules.helper import HelperFunctions
#from helper import helper, packet_parser, stats_calculator
#from helper import format_bps, format_pps, format_bytes

# Optional T-Rex STL imports
try:
    from trex.stl.api import STLStream, STLPktBuilder, STLTXCont, STLFlowStats, STLVM, STLTXSingleBurst
    TREX_STL_AVAILABLE = True
except Exception:
    STLStream = STLPktBuilder = STLTXCont = STLFlowStats = STLVM = None
    TREX_STL_AVAILABLE = False

# Optional scapy import for building/previewing composed packets
try:
    import scapy.all as scapy
    #import scapy.all as scapy
    #from scapy.layers.l2 import LLC,SNAP,MPLS,LLDPDU,Dot1Q,Dot1AD,SNAP
    from scapy.layers.l2 import LLC, SNAP, STP, Dot3, Ether
    from scapy.layers.l2 import Dot3
    #from scapy.layers.l2 import MPLS  # MPLS 在大多数版本中也在 l2 层
   # from scapy.layers.vxlan import NSH  # NSH 通常在 vxlan 模块中
    SCAPY_AVAILABLE = True
except Exception:
    scapy = None
    SCAPY_AVAILABLE = False
    exit()

# Layer presets (template contains placeholders like {src_ip}, {dst_port} etc.)
LAYER_PRESETS = {
    'L2': [
        # Ethernet family
        {'id': 'eth', 'name': 'Ethernet', 'template': "Ether(dst='{dst_mac}', src='{src_mac}')",
         'fields': {
             'dst_mac': {'mode':'fixed','value':'00:02:00:03:04:02','start':'00:02:00:03:04:02','end':'00:02:00:03:04:02','step':1},
             'src_mac': {'mode':'fixed','value':'00:03:00:01:40:01','start':'00:03:00:01:40:01','end':'00:03:00:01:40:01','step':1},
         }
        },
        {'id': 'dot3', 'name': 'Ethernet', 'template': "Dot3(dst='{dst_mac}', src='{src_mac}')",
          'fields': {
             'dst_mac': {'mode':'fixed','value':'ff:ff:ff:ff:ff:ff','start':'00:02:00:03:04:02','end':'00:02:00:03:04:02','step':1},
             'src_mac': {'mode':'fixed','value':'00:03:00:01:40:01','start':'00:03:00:01:40:01','end':'00:03:00:01:40:01','step':1},
         }
        },
        {'id': 'dot1q', 'name': 'Dot1Q (802.1Q)', 'template': "Dot1Q(vlan={vlan_id}, prio={vlan_prio})",
         'fields': {'vlan_id': {'mode':'fixed','value':100,'start':1,'end':4094,'step':1}, 'vlan_prio': {'mode':'fixed','value':0,'start':0,'end':7,'step':1}}},
        {'id': 'dot1ad', 'name': 'Dot1AD (Q-in-Q)', 'template': "Dot1Q(vlan={outer_vlan})/Dot1Q(vlan={inner_vlan})",
         'fields': {'outer_vlan': {'mode':'fixed','value':100,'start':1,'end':4094,'step':1}, 'inner_vlan': {'mode':'fixed','value':200,'start':1,'end':4094,'step':1}}},
        {'id': 'mpls', 'name': 'MPLS', 'template': "MPLS(label={label})", 'fields': {'label': {'mode':'fixed','value':1000,'start':0,'end':1048575,'step':1}}},
        # Discovery / control
        {'id': 'lldp', 'name': 'LLDPDU', 'template': "LLDPDU()", 'fields': {}},
        {'id': 'eapol', 'name': 'EAPOL', 'template': "EAPOL()", 'fields': {}},
        {'id': 'stp', 'name': 'STP', 'template': "STP()", 'fields': {}},
        {'id': 'cdp', 'name': 'CDP', 'template': "CDP()", 'fields': {}},
        # Other L2: SNAP/LLC/etc
        {'id': 'llc', 'name': 'LLC', 'template': "LLC()",'fields': {}},
        {'id': 'snap', 'name': 'SNAP', 'template': "SNAP()",'fields': {}},
        {'id': 'jumbo', 'name': 'Jumbo', 'template': "Jumbo()", 'fields': {}},
        {'id': 'tokenring', 'name': 'TokenRing', 'template': "TokenRing()", 'fields': {}},
        {'id': 'fddi', 'name': 'FDDI', 'template': "FDDI()", 'fields': {}},
        {'id': 'linuxsll', 'name': 'Linux SLL/Cooked', 'template': "Ether()", 'fields': {}},
    ],
    # Wireless (802.11) / RadioTap and many 802.11 related elements
    'WIRELESS': [
        {'id': 'radiotap', 'name': 'RadioTap', 'template': "RadioTap()", 'fields': {}},
        {'id': 'dot11', 'name': 'Dot11', 'template': "Dot11(addr1='{dst_mac}', addr2='{src_mac}', addr3='{bssid}')",
         'fields': {'dst_mac': {'mode':'fixed','value':'ff:ff:ff:ff:ff:ff','start':'ff:ff:ff:ff:ff:ff','end':'ff:ff:ff:ff:ff:ff','step':1},
                    'src_mac': {'mode':'fixed','value':'00:03:00:01:40:01','start':'00:03:00:01:40:01','end':'00:03:00:01:40:01','step':1},
                    'bssid': {'mode':'fixed','value':'00:11:22:33:44:55','start':'00:11:22:33:44:55','end':'00:11:22:33:44:55','step':1}}},
        {'id': 'dot11beacon', 'name': 'Dot11Beacon', 'template': "Dot11Beacon()/Dot11Elt()", 'fields': {}},
        {'id': 'dot11probereq', 'name': 'Dot11ProbeReq', 'template': "Dot11ProbeReq()", 'fields': {}},
        {'id': 'dot11proberesp', 'name': 'Dot11ProbeResp', 'template': "Dot11ProbeResp()", 'fields': {}},
        {'id': 'dot11auth', 'name': 'Dot11Auth', 'template': "Dot11Auth()", 'fields': {}},
        {'id': 'dot11assocreq', 'name': 'Dot11AssoReq', 'template': "Dot11AssoReq()", 'fields': {}},
        {'id': 'dot11assocresp', 'name': 'Dot11AssoResp', 'template': "Dot11AssoResp()", 'fields': {}},
        {'id': 'dot11reassoreq', 'name': 'Dot11ReassoReq', 'template': "Dot11ReassoReq()", 'fields': {}},
        {'id': 'dot11reassoresp', 'name': 'Dot11ReassoResp', 'template': "Dot11ReassoResp()", 'fields': {}},
        {'id': 'dot11disas', 'name': 'Dot11Disas', 'template': "Dot11Disas()", 'fields': {}},
        {'id': 'dot11deauth', 'name': 'Dot11Deauth', 'template': "Dot11Deauth()", 'fields': {}},
        {'id': 'dot11ack', 'name': 'Dot11Ack', 'template': "Dot11Ack()", 'fields': {}},
        {'id': 'dot11rts', 'name': 'Dot11RTS', 'template': "Dot11RTS()", 'fields': {}},
        {'id': 'dot11cts', 'name': 'Dot11CTS', 'template': "Dot11CTS()", 'fields': {}},
        {'id': 'dot11wep', 'name': 'Dot11WEP', 'template': "Dot11WEP()", 'fields': {}},
        {'id': 'dot11qos', 'name': 'Dot11QoS', 'template': "Dot11QoS()", 'fields': {}},
        {'id': 'dot11data', 'name': 'Dot11Data', 'template': "Dot11Data()", 'fields': {}},
        {'id': 'dot11elt', 'name': 'Dot11Elt', 'template': "Dot11Elt()", 'fields': {}},
        {'id': 'radiotap_prism', 'name': 'PrismHeader', 'template': "PrismHeader()", 'fields': {}},
        # Bluetooth / Zigbee
        {'id': 'l2cap', 'name': 'L2CAP_Hdr', 'template': "L2CAP_Hdr()", 'fields': {}},
        {'id': 'zigbeenwk', 'name': 'ZigbeeNWK', 'template': "ZigbeeNWK()", 'fields': {}},
        {'id': 'zigbeeapp', 'name': 'ZigbeeAppDataPayload', 'template': "ZigbeeAppDataPayload()", 'fields': {}},
    ],

    'L3': [
        {'id': 'ipv4', 'name': 'IPv4', 'template': "IP(src='{src_ip}', dst='{dst_ip}', ttl={ttl})",
         'fields': {'src_ip': {'mode':'fixed','value':'16.0.0.1','start':'16.0.0.1','end':'16.0.0.1','step':1},
                    'dst_ip': {'mode':'fixed','value':'48.0.0.1','start':'48.0.0.1','end':'48.0.0.1','step':1},
                    'ttl': {'mode':'fixed','value':64,'start':1,'end':255,'step':1}}},
        {'id': 'ipv6', 'name': 'IPv6', 'template': "IPv6(src='{src_ipv6}', dst='{dst_ipv6}', hlim={hlim})",
         'fields': {'src_ipv6': {'mode':'fixed','value':'fc00::1','start':'fc00::1','end':'fc00::1','step':1},
                    'dst_ipv6': {'mode':'fixed','value':'fd00::2','start':'fd00::2','end':'fd00::2','step':1},
                    'hlim': {'mode':'fixed','value':64,'start':1,'end':255,'step':1}}},

        # Address resolution and ARP family
        {'id': 'arp', 'name': 'ARP', 'template': "ARP(psrc='{src_ip}', pdst='{dst_ip}', hwsrc='{src_mac}', hwdst='{dst_mac}', op={op})",
         'fields': {'src_ip': {'mode':'fixed','value':'16.0.0.1','start':'16.0.0.1','end':'16.0.0.1','step':1},
                    'dst_ip': {'mode':'fixed','value':'48.0.0.1','start':'48.0.0.1','end':'48.0.0.1','step':1},
                    'src_mac': {'mode':'fixed','value':'00:03:00:01:40:01','start':'00:03:00:01:40:01','end':'00:03:00:01:40:01','step':1},
                    'dst_mac': {'mode':'fixed','value':'ff:ff:ff:ff:ff:ff','start':'ff:ff:ff:ff:ff:ff','end':'ff:ff:ff:ff:ff:ff','step':1},
                    'op': {'mode':'fixed','value':1,'start':1,'end':2,'step':1}}},
    ],

    'L4': [
        {'id': 'udp', 'name': 'UDP', 'template': "UDP(sport={src_port}, dport={dst_port})",
         'fields': {'src_port': {'mode':'fixed','value':1025,'start':1,'end':65535,'step':1},
                    'dst_port': {'mode':'fixed','value':80,'start':1,'end':65535,'step':1}}},
        {'id': 'tcp', 'name': 'TCP', 'template': "TCP(sport={src_port}, dport={dst_port}, flags='{flags}')",
         'fields': {'src_port': {'mode':'fixed','value':1025,'start':1,'end':65535,'step':1},
                    'dst_port': {'mode':'fixed','value':80,'start':1,'end':65535,'step':1},
                    'flags': {'mode':'fixed','value':'','start':'','end':'','step':1}}},
        {'id': 'sctp', 'name': 'SCTP', 'template': "SCTP(sport={src_port}, dport={dst_port})",
         'fields': {'src_port': {'mode':'fixed','value':5000,'start':1,'end':65535,'step':1},
                    'dst_port': {'mode':'fixed','value':5001,'start':1,'end':65535,'step':1}}},
        # Common transport placeholders
        {'id': 'raw', 'name': 'RawPayload', 'template': "Raw(load={raw_bin})", 'fields': {'raw_bin': {'mode':'fixed','value':"b'\\x00'","start":"b'\\x00'","end":"b'\\x00'","step":1}}}
    ],

    'TUNNEL': [
        {'id': 'vxlan', 'name': 'VXLAN', 'template': "VXLAN(vni={vni})",
         'fields': {'vni': {'mode':'fixed','value':10,'start':1,'end':16777215,'step':1}}},
        {'id': 'geneve', 'name': 'GENEVE', 'template': "GENEVE(vni={vni})",
         'fields': {'vni': {'mode':'fixed','value':20,'start':1,'end':16777215,'step':1}}},
        {'id': 'nvgre', 'name': 'NVGRE', 'template': "NVGRE()", 'fields': {}},
        {'id': 'ipip', 'name': 'IP-in-IP', 'template': "IP(src='{tunnel_src}', dst='{tunnel_dst}')",
         'fields': {'tunnel_src': {'mode':'fixed','value':'10.0.0.1','start':'10.0.0.1','end':'10.0.0.1','step':1}, 'tunnel_dst': {'mode':'fixed','value':'10.0.0.2','start':'10.0.0.2','end':'10.0.0.2','step':1}}},
        {'id': 'gre', 'name': 'GRE', 'template': "GRE()", 'fields': {}},
        {'id': 'erspan', 'name': 'ERSPAN', 'template': "ERSPAN()", 'fields': {}},
        {'id': 'teb', 'name': 'TEB', 'template': "TEB()", 'fields': {}},
        {'id': 'linux_sll', 'name': 'LinuxCooked', 'template': "CookedLinux()", 'fields': {}},
        {'id': 'loopback', 'name': 'Loopback', 'template': "Loopback()", 'fields': {}}
    ],

    # WAN protocols (best-effort templates)
    'WAN': [
        {'id': 'ppp', 'name': 'PPP', 'template': "PPP()", 'fields': {}},
        {'id': 'pppoe', 'name': 'PPPoE', 'template': "PPPoE()", 'fields': {}},
        {'id': 'pppoed', 'name': 'PPPoE_Discovery', 'template': "PPPoED()", 'fields': {}},
        {'id': 'hdlc', 'name': 'HDLC', 'template': "HDLC()", 'fields': {}},
        {'id': 'fr', 'name': 'FrameRelay', 'template': "FrameRelay()", 'fields': {}},
        {'id': 'chdlc', 'name': 'CHDLC', 'template': "CHDLC()", 'fields': {}},
        {'id': 'ciscohdlc', 'name': 'CISCO_HDLC', 'template': "CISCO_HDLC()", 'fields': {}},
    ],

    # Industrial protocols (placeholders; some require additional scapy contribs)
    'INDUSTRIAL': [
        {'id': 'can', 'name': 'CAN', 'template': "CAN()", 'fields': {}},
        {'id': 'profinet', 'name': 'PROFINET', 'template': "PROFINET()", 'fields': {}},
        {'id': 'ethercat', 'name': 'EtherCAT', 'template': "EtherCAT()", 'fields': {}},
        {'id': 's7', 'name': 'S7Comm', 'template': "S7Comm()", 'fields': {}},
        {'id': 'cotp', 'name': 'COTP', 'template': "COTP()", 'fields': {}},
        {'id': 'tpkt', 'name': 'TPKT', 'template': "TPKT()", 'fields': {}},
        {'id': 'iso_802_3', 'name': 'ISO_802_3', 'template': "ISO_802_3()", 'fields': {}},
    ],

    # Storage network protocols
    'STORAGE': [
        {'id': 'fc', 'name': 'FibreChannel', 'template': "FC()", 'fields': {}},
        {'id': 'fcoe', 'name': 'FCoE', 'template': "FCoE()", 'fields': {}},
        {'id': 'iscsi', 'name': 'iSCSI', 'template': "iSCSI()", 'fields': {}},
    ],

    # Encapsulation / misc
    'ENCAP': [
        {'id': 'vxlan_enc', 'name': 'VXLAN (encap)', 'template': "VXLAN(vni={vni})", 'fields': {'vni': {'mode':'fixed','value':10,'start':0,'end':16777215,'step':1}}},
        {'id': 'geneve_enc', 'name': 'GENEVE (encap)', 'template': "GENEVE(vni={vni})", 'fields': {'vni': {'mode':'fixed','value':20,'start':0,'end':16777215,'step':1}}},
        {'id': 'nvgre_enc', 'name': 'NVGRE', 'template': "NVGRE()", 'fields': {}},
        {'id': 'erspan_enc', 'name': 'ERSPAN', 'template': "ERSPAN()", 'fields': {}},
        {'id': 'linux_cooked', 'name': 'LinuxCooked', 'template': "CookedLinux()", 'fields': {}},
    ],

    # Address resolution & related
    'ADDR': [
        {'id': 'arp', 'name': 'ARP', 'template': "ARP()", 'fields': {}},
        {'id': 'rarp', 'name': 'RARP', 'template': "RARP()", 'fields': {}},
        {'id': 'garp', 'name': 'GARP', 'template': "GARP()", 'fields': {}},
        {'id': 'inarp', 'name': 'InARP', 'template': "InARP()", 'fields': {}},
    ]

}

FIELD_MODES = ['fixed', 'inc', 'dec', 'random']

def extract_placeholders(template: str):
    import re
    return re.findall(r"\{(\w+)\}", template)


class TrafficTab(QWidget):
    """
    支持通过预设层组合构建报文，并为每个占位字段提供模式配置（fixed/inc/dec/random）。
    新增支持：
      - 报文长度配置（mode: fixed/inc/dec/random, fields: value/start/end/step）
      - 速率配置: 百分比(rate_percent) 与 pps（优先使用 pps）
      - 运行模式: continuous / burst (burst_count)
      - 运行时长: run_duration（秒）
    composition is list of dict:
      {
        'family': 'L3',
        'preset_id': 'ipv4',
        'name': 'IPv4',
        'template': "IP(src='{src_ip}', dst='{dst_ip}')",
        'fields': {...}
      }
    """
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.helper = HelperFunctions()
        self.parent_window = parent
        self.composition = []
        # currently selected flow metadata
        self._selected_port_for_view = None
        self._selected_flow_index = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        # Flow browser area
        flows_box = QGroupBox("Flow 浏览 (选择端口查看/编辑该端口下的 flows)")
        fbl = QVBoxLayout(); flows_box.setLayout(fbl)
        port_row = QHBoxLayout()
        port_row.addWidget(QLabel("端口:"))
        self.view_port_sb = QSpinBox(); self.view_port_sb.setRange(0, 65535); self.view_port_sb.setValue(0)
        port_row.addWidget(self.view_port_sb)
        self.load_flows_btn = QPushButton("Load Flows"); self.load_flows_btn.clicked.connect(self._on_load_flows_clicked)
        port_row.addWidget(self.load_flows_btn)
        fbl.addLayout(port_row)

        mid_row = QHBoxLayout()
        self.flows_list = QListWidget()
        self.flows_list.currentRowChanged.connect(self.on_flow_selected)
        # 单击/双击 -> 编辑
        self.flows_list.itemClicked.connect(self._on_flow_item_activated)
        self.flows_list.itemDoubleClicked.connect(self._on_flow_item_activated)
        mid_row.addWidget(self.flows_list, 2)

        act_v = QVBoxLayout()
        self.edit_flow_btn = QPushButton("Edit (加载到层预设界面)"); self.edit_flow_btn.clicked.connect(self._on_edit_flow_clicked)
        self.save_flow_btn = QPushButton("Save Changes"); self.save_flow_btn.clicked.connect(self._on_save_flow_clicked)
        self.delete_flow_btn = QPushButton("Delete Flow"); self.delete_flow_btn.clicked.connect(self._on_delete_flow_clicked)
        self.start_flow_btn = QPushButton("开始打流"); self.start_flow_btn.clicked.connect(self._on_start_flow_clicked)
        self.start_flow_btn.setStyleSheet("QPushButton { background-color: #90EE90; }")
        self.pause_flow_btn = QPushButton("暂停打流"); self.pause_flow_btn.clicked.connect(self._on_pause_flow_clicked)
        self.pause_flow_btn.setStyleSheet("QPushButton { background-color: #FFB6C1; }")
        self.stop_flow_btn = QPushButton("停止打流"); self.stop_flow_btn.clicked.connect(self._on_stop_flow_clicked)
        self.stop_flow_btn.setStyleSheet("QPushButton { background-color: #FFA07A; }")

        act_v.addWidget(self.edit_flow_btn)
        act_v.addWidget(self.save_flow_btn)
        act_v.addWidget(self.delete_flow_btn)
        act_v.addSpacing(10)
        act_v.addWidget(QLabel("流量控制:"))
        act_v.addWidget(self.start_flow_btn)
        act_v.addWidget(self.pause_flow_btn)
        act_v.addWidget(self.stop_flow_btn)
        act_v.addStretch()
        mid_row.addLayout(act_v, 1)

        fbl.addLayout(mid_row)
        layout.addWidget(flows_box)

        # Basic fields
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
        self.family_cb.addItems(['L2','L3','L4','TUNNEL','Raw'])
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
        self.field_table = QTableWidget(0,5)
        self.field_table.setHorizontalHeaderLabels(['Field','Mode','Value/Start','End','Step'])
        self.field_table.horizontalHeader().setStretchLastSection(True)
        right_v.addWidget(self.field_table)
        self.apply_fields_btn = QPushButton("Apply Field Changes"); self.apply_fields_btn.clicked.connect(self.on_apply_field_changes)
        right_v.addWidget(self.apply_fields_btn)
        comp_row.addLayout(right_v)

        pbl.addLayout(comp_row)
        pbl.addWidget(QLabel("组合报文预览:"))
        self.preview_te = QTextEdit(); self.preview_te.setReadOnly(True); self.preview_te.setMaximumHeight(140)
        pbl.addWidget(self.preview_te)

        layout.addWidget(presets_box)

        # Action row: targets + packet length / rate / run-mode / run-duration controls
        action_row = QHBoxLayout()
        action_row.addWidget(QLabel("目标端口 (逗号/范围):"))
        self.target_ports_le = QLineEdit("0")
        action_row.addWidget(self.target_ports_le)

        # Packet length controls group
        pktlen_group = QGroupBox("包长度")
        pl_layout = QHBoxLayout(); pktlen_group.setLayout(pl_layout)
        pl_layout.addWidget(QLabel("模式:"))
        self.pktlen_mode_cb = QComboBox()
        self.pktlen_mode_cb.addItems(FIELD_MODES)
        self.pktlen_mode_cb.setCurrentText('fixed')
        pl_layout.addWidget(self.pktlen_mode_cb)
        pl_layout.addWidget(QLabel("值/起始:"))
        self.pktlen_val_sb = QSpinBox(); self.pktlen_val_sb.setRange(1, 65535); self.pktlen_val_sb.setValue(64)
        pl_layout.addWidget(self.pktlen_val_sb)
        pl_layout.addWidget(QLabel("结束:"))
        self.pktlen_end_sb = QSpinBox(); self.pktlen_end_sb.setRange(1, 65535); self.pktlen_end_sb.setValue(1500)
        pl_layout.addWidget(self.pktlen_end_sb)
        pl_layout.addWidget(QLabel("步长:"))
        self.pktlen_step_sb = QSpinBox(); self.pktlen_step_sb.setRange(1, 65535); self.pktlen_step_sb.setValue(1)
        pl_layout.addWidget(self.pktlen_step_sb)
        action_row.addWidget(pktlen_group)

        # Rate controls
        rate_group = QGroupBox("速率")
        rate_layout = QHBoxLayout(); rate_group.setLayout(rate_layout)
        rate_layout.addWidget(QLabel("百分比:"))
        self.rate_percent_sb = QSpinBox(); self.rate_percent_sb.setRange(1, 100); self.rate_percent_sb.setValue(10)
        rate_layout.addWidget(self.rate_percent_sb)
        rate_layout.addWidget(QLabel("PPS:"))
        self.pps_sb = QSpinBox(); self.pps_sb.setRange(0, 10_000_000); self.pps_sb.setValue(0)  # 0 表示不使用
        rate_layout.addWidget(self.pps_sb)
        action_row.addWidget(rate_group)

        # Run mode + run duration
        run_group = QGroupBox("运行模式")
        run_layout = QHBoxLayout(); run_group.setLayout(run_layout)
        run_layout.addWidget(QLabel("模式:"))
        self.run_mode_cb = QComboBox()
        self.run_mode_cb.addItems(['continuous', 'burst'])
        run_layout.addWidget(self.run_mode_cb)
        run_layout.addWidget(QLabel("突发报文数:"))
        self.burst_count_sb = QSpinBox(); self.burst_count_sb.setRange(1, 10_000_000); self.burst_count_sb.setValue(1000)
        run_layout.addWidget(self.burst_count_sb)
        run_layout.addWidget(QLabel("运行时长(s, 0=无限):"))
        self.run_duration_sb = QSpinBox(); self.run_duration_sb.setRange(0, 24*3600); self.run_duration_sb.setValue(0)
        run_layout.addWidget(self.run_duration_sb)
        action_row.addWidget(run_group)

        # Save / add buttons
        self.save_local_btn = QPushButton("仅保存本地配置"); self.save_local_btn.clicked.connect(self.on_save_local)
        action_row.addWidget(self.save_local_btn)
        self.add_to_device_btn = QPushButton("下发到 T-Rex 并保存"); self.add_to_device_btn.clicked.connect(self.on_add_to_device)
        action_row.addWidget(self.add_to_device_btn)

        layout.addLayout(action_row)

        runtime_row = QHBoxLayout()
        runtime_row.addWidget(QLabel("流运行时间:"))
        self.runtime_label = QLabel("00:00:00")
        runtime_row.addWidget(self.runtime_label)
        runtime_row.addStretch()
        layout.addLayout(runtime_row)
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

    # ---------------- small helpers to avoid int(None) errors ----------------
    def _safe_int(self, v, default=0):
        try:
            if v is None:
                return default
            if isinstance(v, bool):
                return int(v)
            if isinstance(v, (int, float)):
                return int(v)
            s = str(v).strip()
            if s == '':
                return default
            return int(s)
        except Exception:
            return default

    def _safe_set_spin(self, spin: QSpinBox, v, default=None):
        try:
            if default is None:
                default = spin.value()
            spin.setValue(self._safe_int(v, default))
        except Exception:
            # ignore invalid set
            pass

    # ---------------- Flow browser helpers ----------------
    def _on_load_flows_clicked(self):
        port = int(self.view_port_sb.value())
        self._selected_port_for_view = port
        self._refresh_flows_ui(port)

    def _refresh_flows_ui(self, port: int):
        """
        Populate the flows_list for the given port from controller.flow_configs.
        """
        self.flows_list.clear()
        flows_for_port = []
        try:
            flows_for_port = self.controller.flow_configs.get(port, [])
        except Exception:
            flows_for_port = []
        for idx, f in enumerate(flows_for_port):
            name = f.get('name') or f.get('params', {}).get('name') or f"flow_{idx}"
            active = f.get('active', False)
            paused = f.get('paused', False)
            status_text = "● 运行中" if active else "○ 已停止"
            if paused:
                status_text = "⏸ 已暂停"
            # 显示运行时长（如果存在）
            params = f.get('params', {}) or {}
            run_duration = params.get('run_duration', None)
            dur_text = f" / {run_duration}s" if run_duration else ""
            item = QListWidgetItem(f"[{idx}] {name} - {status_text}{dur_text}")
            self.flows_list.addItem(item)
        # Clear selection and editor UI to avoid retention
        self._selected_flow_index = None
        self.composition = []
        self.composition_list.clear()
        self.field_table.setRowCount(0)
        self.preview_te.clear()
        self.append_status(f"Loaded {len(flows_for_port)} flows for port {port}")

    def on_flow_selected(self, idx: int):
        # Clear UI preview of previous selection to avoid retained data
        self.field_table.setRowCount(0)
        self.composition_list.clear()
        self.preview_te.clear()

        if idx < 0:
            self._selected_flow_index = None
            return
        port = self._selected_port_for_view
        if port is None:
            return
        try:
            flows = self.controller.flow_configs.get(port, [])
            if idx >= len(flows):
                return
            flow = flows[idx]
            self._selected_flow_index = idx
            name = flow.get('name') or flow.get('params', {}).get('name', '')
            params = flow.get('params', {})
            comp_len = len(params.get('composition', [])) if isinstance(params, dict) else 0
            self.append_status(f"Selected flow [{idx}] {name} (layers: {comp_len})")
        except Exception as e:
            traceback.print_exc()
            self.append_status(f"选择 flow 时出错: {e}", "错误")

    def _on_flow_item_activated(self, item):
        if item is None:
            return
        row = self.flows_list.row(item)
        port = self._selected_port_for_view
        if port is None:
            port = int(self.view_port_sb.value())
            self._selected_port_for_view = port
            if self.flows_list.count() == 0:
                self._refresh_flows_ui(port)
        self._selected_flow_index = row
        self._load_flow_into_editor(port, row)

    def _load_flow_into_editor(self, port, idx):
        try:
            flows = self.controller.flow_configs.get(port, [])
            if idx < 0 or idx >= len(flows):
                return
            flow = flows[idx]
            params = flow.get('params', {}) or {}
            # Clear editor
            self.composition = []
            self.composition_list.clear()
            self.field_table.setRowCount(0)
            # Load base fields
            self.flow_name_le.setText(params.get('name', self.flow_name_le.text()))
            if isinstance(params, dict):
                if 'src_mac' in params and params.get('src_mac') is not None:
                    self.src_mac_le.setText(str(params.get('src_mac')))
                if 'dst_mac' in params and params.get('dst_mac') is not None:
                    self.dst_mac_le.setText(str(params.get('dst_mac')))
                if 'src_ip' in params and params.get('src_ip') is not None:
                    self.src_ip_le.setText(str(params.get('src_ip')))
                if 'dst_ip' in params and params.get('dst_ip') is not None:
                    self.dst_ip_le.setText(str(params.get('dst_ip')))
                # safe set spinboxes
                self._safe_set_spin(self.src_port_sb, params.get('src_port'), self.src_port_sb.value())
                self._safe_set_spin(self.dst_port_sb, params.get('dst_port'), self.dst_port_sb.value())
                if 'target_ports' in params and params.get('target_ports') is not None:
                    try:
                        self.target_ports_le.setText(",".join([str(x) for x in params.get('target_ports', [])]))
                    except Exception:
                        pass
                # load pkt len / rate / run mode / run duration if exist (use safe conversions)
                pkt_len = params.get('pkt_len', {})
                if pkt_len:
                    mode = pkt_len.get('mode', 'fixed') or 'fixed'
                    try:
                        self.pktlen_mode_cb.setCurrentText(mode)
                    except Exception:
                        pass
                    self._safe_set_spin(self.pktlen_val_sb, pkt_len.get('value'), self.pktlen_val_sb.value())
                    self._safe_set_spin(self.pktlen_end_sb, pkt_len.get('end'), self.pktlen_end_sb.value())
                    self._safe_set_spin(self.pktlen_step_sb, pkt_len.get('step'), self.pktlen_step_sb.value())
                self._safe_set_spin(self.rate_percent_sb, params.get('rate_percent'), self.rate_percent_sb.value())
                # pps may be None => set to 0 if None
                pps_val = params.get('pps', None)
                if pps_val is None:
                    self.pps_sb.setValue(0)
                else:
                    self._safe_set_spin(self.pps_sb, pps_val, 0)
                run_mode = params.get('run_mode', None)
                if run_mode:
                    try:
                        self.run_mode_cb.setCurrentText(run_mode)
                    except Exception:
                        pass
                if params.get('burst_count') is not None:
                    self._safe_set_spin(self.burst_count_sb, params.get('burst_count'), self.burst_count_sb.value())
                # run duration
                if params.get('run_duration') is not None:
                    self._safe_set_spin(self.run_duration_sb, params.get('run_duration'), self.run_duration_sb.value())
                else:
                    # keep existing value (default 0)
                    pass
            # Load composition deep-copied so editing doesn't immediately change stored flow until saved
            comp = params.get('composition', []) if isinstance(params, dict) else []
            self.composition = copy.deepcopy(comp)
            # Populate composition_list UI
            for layer in self.composition:
                self.composition_list.addItem(QListWidgetItem(f"{layer.get('family')} - {layer.get('name')}"))
            self.update_preview()
            self.append_status(f"Loaded flow [{idx}] from port {port} into editor for editing.")
            runtime = flow.get('run_time', None)
            if runtime is not None:
                try:
                    # runtime is seconds
                    hh = int(runtime) // 3600
                    mm = (int(runtime) % 3600) // 60
                    ss = int(runtime) % 60
                    self.runtime_label.setText(f"{hh:02d}:{mm:02d}:{ss:02d}")
                except Exception:
                    pass
            else:
                self.runtime_label.setText("00:00:00")
            self.append_status(f"Loaded flow [{idx}] into editor.")

        except Exception as e:
            traceback.print_exc()
            self.append_status(f"加载 flow 到编辑器出错: {e}", "错误")

    def _on_edit_flow_clicked(self):
        idx = self._selected_flow_index
        port = self._selected_port_for_view
        if port is None or idx is None:
            QMessageBox.information(self, "未选择", "请先在上方选择端口并选中一个 flow 再点击 Edit。")
            return
        self._load_flow_into_editor(port, idx)

    def _on_save_flow_clicked(self):
        idx = self._selected_flow_index
        port = self._selected_port_for_view
        if port is None or idx is None:
            QMessageBox.information(self, "未选择", "请先选择一个 flow 后再保存。")
            return
        params, err = self._collect_params()
        if err:
            QMessageBox.warning(self, "保存失败", err)
            self.append_status(err, "错误")
            return
        params['composition'] = copy.deepcopy(self.composition)
        try:
            flows = self.controller.flow_configs.setdefault(port, [])
            if idx < 0 or idx >= len(flows):
                QMessageBox.warning(self, "保存失败", "选中的 flow 索引无效")
                return
            flows[idx]['params'] = params
            flows[idx]['name'] = params.get('name', flows[idx].get('name'))
            if hasattr(self.controller, 'update_flow_on_port'):
                try:
                    ok, msg = self.controller.update_flow_on_port(port, idx, flows[idx])
                    if ok:
                        self.append_status(f"已保存并更新端口 {port} 上的 flow [{idx}] ({msg})", "信息")
                    else:
                        self.append_status(f"更新端口 flow 失败: {msg}", "错误")
                except Exception as e:
                    traceback.print_exc()
                    self.append_status(f"调用 controller.update_flow_on_port 失败: {e}", "警告")
                    try:
                        ok, msg = self.controller.add_flow_to_port(port, flows[idx])
                        if ok:
                            self.append_status(f"已使用 add_flow_to_port 保存端口 {port} flow [{idx}] ({msg})", "信息")
                        else:
                            self.append_status(f"通过 add_flow_to_port 保存失败: {msg}", "错误")
                    except Exception as e2:
                        traceback.print_exc()
                        self.append_status(f"保存到控制器失败: {e2}", "错误")
            else:
                try:
                    print("no_update_flow_port")
                    ok, msg = self.controller.add_flow_to_port(port, flows[idx])
                    if ok:
                        self.append_status(f"已保存端口 {port} flow [{idx}] (add_flow_to_port: {msg})", "信息")
                    else:
                        self.append_status(f"保存失败: {msg}", "错误")
                except Exception as e:
                    traceback.print_exc()
                    self.append_status(f"调用 controller.add_flow_to_port 失败: {e}", "错误")
            self._refresh_flows_ui(port)
        except Exception as e:
            traceback.print_exc()
            self.append_status(f"保存 flow 出错: {e}", "错误")

    def _on_delete_flow_clicked(self):
        idx = self._selected_flow_index
        port = self._selected_port_for_view
        if port is None or idx is None:
            QMessageBox.information(self, "未选择", "请先选择一个 flow 再删除。")
            return
        try:
            flows = self.controller.flow_configs.get(port, [])
            if idx < 0 or idx >= len(flows):
                QMessageBox.warning(self, "删除失败", "选中的 flow 索引无效。")
                return
            if hasattr(self.controller, 'remove_flow_from_port'):
                try:
                    ok, msg = self.controller.remove_flow_from_port(port, idx)
                    if ok:
                        self.append_status(f"已从控制器移除端口 {port} 的 flow [{idx}] ({msg})", "信息")
                    else:
                        self.append_status(f"从控制器移除 flow 失败: {msg}", "警告")
                except Exception as e:
                    traceback.print_exc()
                    self.append_status(f"调用 remove_flow_from_port 失败: {e}", "警告")
            try:
                flows.pop(idx)
            except Exception:
                pass
            self._selected_flow_index = None
            self.composition = []
            self.composition_list.clear()
            self.field_table.setRowCount(0)
            self._refresh_flows_ui(port)
            self.append_status(f"Deleted flow [{idx}] for port {port}")
        except Exception as e:
            traceback.print_exc()
            self.append_status(f"删除 flow 出错: {e}", "错误")

    # ---------------- Flow control methods ----------------
    def _on_start_flow_clicked(self):
        """开始打流"""
        idx = self._selected_flow_index
        port = self._selected_port_for_view
        if port is None or idx is None:
            QMessageBox.information(self, "未选择", "请先选择端口和flow")
            return

        try:
            flows = self.controller.flow_configs.get(port, [])
            if idx < 0 or idx >= len(flows):
                QMessageBox.warning(self, "错误", "选中的flow索引无效")
                return

            flow = flows[idx]
            flow_name = flow.get('name', f"flow_{idx}")

            if not getattr(self.controller, 'is_connected', False):
                QMessageBox.warning(self, "连接错误", "T-Rex未连接，请先连接T-Rex设备")
                return

            params = flow.get('params', {})
            # Ensure safe retrieval
            pps = params.get('pps', None)
            rate_percent = params.get('rate_percent', None)
            run_mode = params.get('run_mode', 'continuous')
            burst_count = params.get('burst_count', None)
            run_duration = params.get('run_duration', None)

            # If pps is set, do NOT pass percentage to controller (pps takes precedence)
            if pps:
                pps = self.helper.format_pps(pps)
                rate_to_pass = None
            else:
                rate_to_pass = rate_percent

            # create streams (they contain enough meta for controller if needed)
            streams, err = self.create_streams_from_composition(params)
            if err and not streams:
                QMessageBox.warning(self, "流生成失败", f"无法生成流数据: {err}")
                return

            try:
                if hasattr(self.controller, 'start_traffic'):
                    success, message, stream_id_list = self.controller.start_traffic(
                        streams=streams,
                        ports=[port],
                        rate_percent=rate_to_pass,
                        pps=pps,
                        duration=run_duration
                    )
                    if success:
                        flow['active'] = True
                        flow['paused'] = False
                        flow['stream_id_list'] = stream_id_list
                        self.append_status(f"开始打流成功: {flow_name} (端口 {port})", "成功")
                        self._update_flow_status_display(port, idx, True)
                    else:
                        QMessageBox.warning(self, "打流失败", f"开始打流失败: {message}")
                        self.append_status(f"开始打流失败: {message}", "错误")
                else:
                    # fallback: best-effort via controller.client
                    if hasattr(self.controller, 'client') and self.controller.client:
                        try:
                            # If controller.client supports starting with total_pkts or pps, prefer that
                            if run_mode == 'burst' and burst_count:
                                try:
                                    # some clients accept total_pkts kwarg
                                    self.controller.client.start(ports=[port], total_pkts=burst_count)
                                except TypeError:
                                    self.controller.client.start(ports=[port], mult="1")
                            else:
                                # continuous: if pps specified, on some clients may be configured elsewhere
                                self.controller.client.start(ports=[port], mult="1")
                            flow['active'] = True
                            flow['paused'] = False
                            self.append_status(f"开始打流: {flow_name} (端口 {port})", "成功")
                            self._update_flow_status_display(port, idx, True)
                        except Exception:
                            traceback.print_exc()
                            QMessageBox.warning(self, "打流失败", "调用 T-Rex 客户端打流失败")
                    else:
                        QMessageBox.warning(self, "错误", "无法访问T-Rex客户端")
            except Exception as e:
                traceback.print_exc()
                QMessageBox.warning(self, "异常", f"开始打流时发生异常: {str(e)}")
                self.append_status(f"开始打流异常: {str(e)}", "错误")
        except Exception as e:
            traceback.print_exc()
            QMessageBox.warning(self, "错误", f"开始打流失败: {str(e)}")
            self.append_status(f"开始打流失败: {str(e)}", "错误")

    def _on_pause_flow_clicked(self):
        """暂停打流"""
        idx = self._selected_flow_index
        port = self._selected_port_for_view
        if port is None or idx is None:
            QMessageBox.information(self, "未选择", "请先选择端口和flow")
            return

        try:
            flows = self.controller.flow_configs.get(port, [])
            if idx < 0 or idx >= len(flows):
                QMessageBox.warning(self, "错误", "选中的flow索引无效")
                return

            flow = flows[idx]
            flow_name = flow.get('name', f"flow_{idx}")

            if not flow.get('active', False):
                QMessageBox.information(self, "提示", f"流 {flow_name} 未在运行状态")
                return

            if hasattr(self.controller, 'pause_traffic'):
                success, message = self.controller.pause_traffic(ports=[port])
                if success:
                    flow['paused'] = True
                    self.append_status(f"暂停打流: {flow_name} (端口 {port})", "信息")
                    self._update_flow_status_display(port, idx, True, True)
                else:
                    QMessageBox.warning(self, "暂停失败", f"暂停打流失败: {message}")
            else:
                if hasattr(self.controller, 'client') and self.controller.client:
                    try:
                        self.controller.client.pause(ports=[port])
                        flow['paused'] = True
                        self.append_status(f"暂停打流: {flow_name} (端口 {port})", "信息")
                        self._update_flow_status_display(port, idx, True, True)
                    except Exception:
                        traceback.print_exc()
                        QMessageBox.warning(self, "暂停失败", "调用客户端 pause 失败")
                else:
                    QMessageBox.warning(self, "错误", "无法访问T-Rex客户端")
        except Exception as e:
            traceback.print_exc()
            QMessageBox.warning(self, "错误", f"暂停打流失败: {str(e)}")
            self.append_status(f"暂停打流失败: {str(e)}", "错误")

    def _on_stop_flow_clicked(self):
        """停止打流"""
        idx = self._selected_flow_index
        port = self._selected_port_for_view
        if port is None or idx is None:
            QMessageBox.information(self, "未选择", "请先选择端口和flow")
            return

        try:
            flows = self.controller.flow_configs.get(port, [])
            if idx < 0 or idx >= len(flows):
                QMessageBox.warning(self, "错误", "选中的flow索引无效")
                return

            flow = flows[idx]
            flow_name = flow.get('name', f"flow_{idx}")

            if hasattr(self.controller, 'stop_traffic'):
                success, message = self.controller.stop_traffic(ports=port)
                if success:
                    flow['active'] = False
                    flow['paused'] = False
                    self.append_status(f"停止打流: {flow_name} (端口 {port})", "信息")
                    self._update_flow_status_display(port, idx, False)
                else:
                    QMessageBox.warning(self, "停止失败", f"停止打流失败: {message}")
            else:
                if hasattr(self.controller, 'client') and self.controller.client:
                    try:
                        self.controller.client.stop(ports=[port])
                        flow['active'] = False
                        flow['paused'] = False
                        self.append_status(f"停止打流: {flow_name} (端口 {port})", "信息")
                        self._update_flow_status_display(port, idx, False)
                    except Exception:
                        traceback.print_exc()
                        QMessageBox.warning(self, "停止失败", "调用客户端 stop 失败")
                else:
                    QMessageBox.warning(self, "错误", "无法访问T-Rex客户端")
        except Exception as e:
            traceback.print_exc()
            QMessageBox.warning(self, "错误", f"停止打流失败: {str(e)}")
            self.append_status(f"停止打流失败: {str(e)}", "错误")

    def _update_flow_status_display(self, port: int, flow_index: int, active: bool, paused: bool = False):
        """更新flow列表中的状态显示"""
        try:
            current_row = self.flows_list.currentRow()
            flows = self.controller.flow_configs.get(port, [])
            if 0 <= flow_index < len(flows):
                flow = flows[flow_index]
                name = flow.get('name', f"flow_{flow_index}")
                status_text = "● 运行中" if active else "○ 已停止"
                if paused:
                    status_text = "⏸ 已暂停"
                params = flow.get('params', {}) or {}
                run_duration = params.get('run_duration', None)
                dur_text = f" / {run_duration}s" if run_duration else ""
                item_text = f"[{flow_index}] {name} - {status_text}{dur_text}"
                if flow_index < self.flows_list.count():
                    item = self.flows_list.item(flow_index)
                    if item:
                        item.setText(item_text)
                if current_row >= 0:
                    self.flows_list.setCurrentRow(current_row)
        except Exception as e:
            self.append_status(f"更新状态显示失败: {str(e)}", "警告")

    # ---------------- Composition operations ----------------
    def on_add_layer(self):
        preset = self.preset_cb.currentData()
        if not preset:
            QMessageBox.warning(self, "错误", "未选择预设")
            return
        template = preset['template']
        placeholders = extract_placeholders(template)
        fields = {}
        preset_fields = preset.get('fields', {}) or {}
        for fname, fcfg in preset_fields.items():
            fc = dict(fcfg)
            fc.setdefault('mode', 'fixed')
            fc.setdefault('value', fc.get('value', ''))
            fc.setdefault('start', fc.get('start', fc.get('value', '')))
            fc.setdefault('end', fc.get('end', fc.get('start', fc.get('value', ''))))
            fc.setdefault('step', int(fc.get('step', 1) or 1))
            fc['name'] = fname
            fields[fname] = fc
        # defaults for common placeholders
        defaults = {
            'src_mac': self.src_mac_le.text().strip(),
            'dst_mac': self.dst_mac_le.text().strip(),
            'src_ip': self.src_ip_le.text().strip(),
            'dst_ip': self.dst_ip_le.text().strip(),
            'src_ipv6': "fc00::1",
            'dst_ipv6': "fd00::2",
            'src_port': int(self.src_port_sb.value()),
            'dst_port': int(self.dst_port_sb.value()),
            'vlan_id': 100,
            'vlan_prio': 0,
            'vni': 10,
            'eth_type': 2048,
            'ttl': 64,
            'hlim': 64,
            'flags': ''
        }
        for ph in placeholders:
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
            it = QTableWidgetItem(fname)
            it.setFlags(Qt.ItemIsEnabled)
            self.field_table.setItem(r, 0, it)
            mode_cb = QComboBox()
            mode_cb.addItems(FIELD_MODES)
            mode_cb.setCurrentText(fcfg.get('mode', 'fixed'))
            self.field_table.setCellWidget(r, 1, mode_cb)
            val_it = QTableWidgetItem(str(fcfg.get('value', '')))
            self.field_table.setItem(r, 2, val_it)
            end_it = QTableWidgetItem(str(fcfg.get('end', '')))
            self.field_table.setItem(r, 3, end_it)
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

            # composition from editor
            params['composition'] = copy.deepcopy(self.composition)

            # packet length param
            pkt_len = {
                'mode': self.pktlen_mode_cb.currentText(),
                'value': int(self.pktlen_val_sb.value()),
                'start': int(self.pktlen_val_sb.value()),
                'end': int(self.pktlen_end_sb.value()),
                'step': int(self.pktlen_step_sb.value())
            }
            params['pkt_len'] = pkt_len            # rate / pps
            params['rate_percent'] = int(self.rate_percent_sb.value())
            pps_val = int(self.pps_sb.value())
            params['pps'] = pps_val if pps_val > 0 else None

            # run mode / burst count / run duration
            params['run_mode'] = self.run_mode_cb.currentText()
            params['burst_count'] = int(self.burst_count_sb.value()) if params['run_mode'] == 'burst' else None
            run_d = int(self.run_duration_sb.value())
            params['run_duration'] = run_d if run_d > 0 else None

            return params, None
        except Exception as e:
            traceback.print_exc()
            return None, f"参数收集异常: {e}"

    # ---------------- Field value resolution & helpers ----------------
    def _is_ip(self, s: str):
        try:
            if ':' in str(s):
                ipaddress.IPv6Address(str(s))
            else:
                ipaddress.IPv4Address(str(s))
            return True
        except Exception:
            return False

    def _safe_ip_to_int(self, ip_str, is_ipv6=False):
        try:
            if is_ipv6:
                ip_obj = ipaddress.IPv6Address(ip_str)
                ip_int = int(ip_obj)
                return ip_int if ip_int >= 0 else (1 << 128) + ip_int
            else:
                return int(ipaddress.IPv4Address(ip_str))
        except (ipaddress.AddressValueError, ValueError) as e:
            self.append_status(f"IP地址转换错误: {ip_str} - {str(e)}", "错误")
            if is_ipv6:
                return int(ipaddress.IPv6Address("::1"))
            else:
                return int(ipaddress.IPv4Address("127.0.0.1"))

    def _safe_int_to_ip(self, ip_int, is_ipv6=False):
        try:
            if is_ipv6:
                if ip_int < 0:
                    ip_int = (1 << 128) + ip_int
                elif ip_int >= (1 << 128):
                    ip_int = ip_int % (1 << 128)
                return str(ipaddress.IPv6Address(ip_int))
            else:
                if ip_int < 0:
                    ip_int = (1 << 32) + ip_int
                elif ip_int >= (1 << 32):
                    ip_int = ip_int % (1 << 32)
                return str(ipaddress.IPv4Address(ip_int))
        except Exception as e:
            self.append_status(f"整数转IP错误: {ip_int} - {str(e)}", "错误")
            if is_ipv6:
                return "::1"
            else:
                return "127.0.0.1"

    def resolve_field_value(self, field_cfg: dict, seq_index: int):
        mode = field_cfg.get('mode', 'fixed')
        field_name = field_cfg.get('name', '')
        is_ip_field = 'ip' in field_name.lower()
        sample_value = field_cfg.get('value', field_cfg.get('start', ''))
        is_ipv6 = ':' in str(sample_value) and is_ip_field
        if mode == 'fixed':
            return field_cfg.get('value', '')
        elif mode == 'random':
            start = field_cfg.get('start', '')
            end = field_cfg.get('end', '')
            if is_ip_field:
                try:
                    start_int = self._safe_ip_to_int(start, is_ipv6)
                    end_int = self._safe_ip_to_int(end, is_ipv6)
                    if start_int > end_int:
                        start_int, end_int = end_int, start_int
                    rand_int = random.randint(start_int, end_int)
                    return self._safe_int_to_ip(rand_int, is_ipv6)
                except Exception as e:
                    self.append_status(f"IP随机生成错误: {str(e)}", "警告")
                    return field_cfg.get('value', '')
            else:
                try:
                    s = int(start) if str(start).strip() else 0
                    e = int(end) if str(end).strip() else 65535
                    if s > e:
                        s, e = e, s
                    return str(random.randint(s, e))
                except Exception:
                    options = [start, end]
                    valid_options = [opt for opt in options if str(opt).strip()]
                    return random.choice(valid_options) if valid_options else field_cfg.get('value', '')
        elif mode in ('inc', 'dec'):
            try:
                base_str = field_cfg.get('start', field_cfg.get('value', ''))
                step = int(field_cfg.get('step', 1))
                if is_ip_field:
                    base_int = self._safe_ip_to_int(base_str, is_ipv6)
                    if mode == 'inc':
                        result_int = base_int + seq_index * step
                    else:
                        result_int = base_int - seq_index * step
                    return self._safe_int_to_ip(result_int, is_ipv6)
                else:
                    base_val = int(base_str) if str(base_str).strip() else 0
                    if mode == 'inc':
                        result_val = base_val + seq_index * step
                    else:
                        result_val = base_val - seq_index * step
                    return str(result_val)
            except Exception as e:
                self.append_status(f"递增/递减模式错误: {str(e)}", "警告")
                return field_cfg.get('value', '')
        return field_cfg.get('value', '')

    def _compute_pkt_sizes_from_params(self, params):
        """
        根据 params['pkt_len'] 生成 sizes 列表用于 create_streams_from_composition。
        支持 mode: fixed/inc/dec/random
        """
        try:
            cfg = params.get('pkt_len', {})
            mode = cfg.get('mode', 'fixed')
            start = int(cfg.get('start', cfg.get('value', 64) or 64))
            end = int(cfg.get('end', start))
            step = int(cfg.get('step', 1) or 1)
            sizes = []
            if mode == 'fixed':
                sizes = [max(1, start)]
            elif mode == 'inc':
                if start <= end:
                    sizes = list(range(start, end + 1, step))
                else:
                    sizes = list(range(start, end - 1, -step))
            elif mode == 'dec':
                if start >= end:
                    sizes = list(range(start, end - 1, -step))
                else:
                    sizes = list(range(start, end + 1, step))
            elif mode == 'random':
                # generate a small set of random sizes to create multiple stream templates
                samples = 5
                lower = min(start, end)
                upper = max(start, end) if end >= lower else lower
                for _ in range(samples):
                    sizes.append(random.randint(lower, upper))
            # ensure at least one valid size
            if not sizes:
                sizes = [64]
            # clip to MTU-like bounds
            cleaned = [max(1, min(65535, int(x))) for x in sizes]
            return cleaned
        except Exception:
            return [64]

    # ---------------- Create streams from composition (trex VM generation supporting IPv6) ----------------
    def create_streams_from_composition(self, params):
        import traceback, ipaddress

        trex_ok = TREX_STL_AVAILABLE
        scapy_ok = SCAPY_AVAILABLE

        comp = params.get('composition', [])
        rate = float(params.get('rate_percent', 10.0) or 0)
        pps = params.get('pps', None)
        run_mode = params.get('run_mode', 'continuous')
        burst_count = params.get('burst_count', None)
        run_duration = params.get('run_duration', None)
        flow_type = (params.get('flow_type') or '').upper()

        def pkt_field_for(fname, l4_proto='UDP', is_ipv6=False):
            f = fname.lower()
            if 'src_ip' == f or f.endswith('_src_ip') or f in ('srcip','src_ip'):
                return 'IP.src'
            if 'dst_ip' == f or f.endswith('_dst_ip') or f in ('dstip','dst_ip','dst_ip'):
                return 'IP.dst'
            if 'src_ipv6' == f or f.endswith('_src_ipv6') or f in ('srcipv6','src_ipv6'):
                return 'IPv6.src'
            if 'dst_ipv6' == f or f.endswith('_dst_ipv6') or f in ('dstipv6','dst_ipv6','dst_ipv6'):
                return 'IPv6.dst'
            if 'src_port' == f or f == 'sport' or f.endswith('src_port'):
                return f"{l4_proto}.sport"
            if 'dst_port' == f or f == 'dport' or f.endswith('dst_port'):
                return f"{l4_proto}.dport"
            if 'src_mac' == f or f == 'smac':
                return 'ETH.src'
            if 'dst_mac' == f or f == 'dmac':
                return 'ETH.dst'
            if 'vlan' in f or 'vlan_id' == f:
                return 'Dot1Q.vlan'
            if 'ip' in f:
                return 'IPv6.src' if is_ipv6 else 'IP.src'
            if 'port' in f:
                return f"{l4_proto}.sport"
            return None

        def build_base_packet_for_size(sz=None):
            try:
                if scapy_ok:
                    payload = b''
                    layers = []
                    for layer in comp:
                        tpl = layer.get('template','')
                        fields = layer.get('fields', {})
                        # detect layer type by template/preset id heuristics
                        if 'Ether' in tpl or layer.get('preset_id','').lower() == 'eth':
                            src = fields.get('src_mac',{}).get('value') or params.get('src_mac')
                            dst = fields.get('dst_mac',{}).get('value') or params.get('dst_mac')
                            layers.append(scapy.Ether(src=src, dst=dst))
                        elif 'Dot3' in tpl or layer.get('preset_id','').lower() == 'dot3':
                            src = fields.get('src_mac',{}).get('value') or params.get('src_mac')
                            dst = fields.get('dst_mac',{}).get('value') or params.get('dst_mac')
                            layers.append(scapy.Dot3(src=src, dst=dst))
                        elif 'LLC' in tpl or layer.get('preset_id','').lower() == 'llc':
                            layers.append(scapy.LLC())
                        elif 'Dot1Q' in tpl or layer.get('preset_id','').lower() == 'vlan':
                            vlan_id = fields.get('vlan_id',{}).get('value') or params.get('vlan_id')
                            vlan_prio = fields.get('vlan_prio',{}).get('value') or params.get('vlan_prio')
                            layers.append(scapy.Dot1Q(vlan=vlan_id, prio=vlan_prio))
                        elif 'IPv6' in tpl or layer.get('preset_id','').lower() == 'ipv6':
                            src = fields.get('src_ipv6',{}).get('value') or params.get('src_ipv6')
                            dst = fields.get('dst_ipv6',{}).get('value') or params.get('dst_ipv6')
                            hlim = fields.get('hlim',{}).get('value') or params.get('hlim')
                            if hlim is None:
                                pkt_ipv6 = scapy.IPv6(src=src, dst=dst)
                            else:
                                pkt_ipv6 = scapy.IPv6(src=src, dst=dst, hlim=int(hlim))
                            layers.append(pkt_ipv6)
                        elif 'IP(' in tpl or layer.get('preset_id','').lower() == 'ipv4' or layer.get('preset_id','').lower() == 'ipip':
                            src = fields.get('src_ip',{}).get('value') or params.get('src_ip')
                            dst = fields.get('dst_ip',{}).get('value') or params.get('dst_ip')
                            ttl = fields.get('ttl',{}).get('value') or params.get('ttl')
                            if ttl is None:
                                pkt_ip = scapy.IP(src=src, dst=dst)
                            else:
                                pkt_ip = scapy.IP(src=src, dst=dst, ttl=int(ttl))
                            layers.append(pkt_ip)
                        elif 'UDP' in tpl or layer.get('preset_id','').lower() == 'udp':
                            sport = int(fields.get('src_port',{}).get('value') or params.get('src_port') or 1025)
                            dport = int(fields.get('dst_port',{}).get('value') or params.get('dst_port') or 80)
                            layers.append(scapy.UDP(sport=sport, dport=dport))
                        elif 'TCP' in tpl or layer.get('preset_id','').lower() == 'tcp':
                            sport = int(fields.get('src_port',{}).get('value') or params.get('src_port') or 1025)
                            dport = int(fields.get('dst_port',{}).get('value') or params.get('dst_port') or 80)
                            flags = fields.get('flags',{}).get('value') or params.get('flags') or ''
                            layers.append(scapy.TCP(sport=sport, dport=dport, flags=flags))
                        elif 'SCTP' in tpl or layer.get('preset_id','').lower() == 'sctp':
                            # scapy may or may not have SCTP class available
                            sport = int(fields.get('src_port',{}).get('value') or params.get('src_port') or 5000)
                            dport = int(fields.get('dst_port',{}).get('value') or params.get('dst_port') or 5001)
                            SCTP_cls = getattr(scapy, 'SCTP', None)
                            if SCTP_cls:
                                layers.append(SCTP_cls(sport=sport, dport=dport))
                            else:
                                # fallback: create UDP placeholder if SCTP not available
                                layers.append(scapy.UDP(sport=sport, dport=dport))
                        elif 'VXLAN' in tpl or layer.get('preset_id','').lower() == 'vxlan':
                            vni = int(fields.get('vni',{}).get('value') or params.get('vni') or 0)
                            VXLAN_cls = getattr(scapy, 'VXLAN', None)
                            if VXLAN_cls:
                                layers.append(VXLAN_cls(vni=vni))
                            else:
                                # no vxlan in scapy, skip
                                pass
                        elif 'GENEVE' in tpl or layer.get('preset_id','').lower() == 'geneve':
                            # scapy GENEVE support may vary
                            GENEVE_cls = getattr(scapy, 'GENEVE', None)
                            vni = int(fields.get('vni',{}).get('value') or params.get('vni') or 0)
                            if GENEVE_cls:
                                layers.append(GENEVE_cls(vni=vni))
                        elif 'GRE' in tpl or layer.get('preset_id','').lower() == 'gre':
                            GRE_cls = getattr(scapy, 'GRE', None)
                            if GRE_cls:
                                layers.append(GRE_cls())
                        elif 'Raw' in tpl or layer.get('preset_id','').lower() == 'raw':
                            raw_val = fields.get('raw_bin',{}).get('value') or b'\x00'
                            # attempt to eval a bytes literal safely
                            try:
                                raw_bytes = eval(raw_val) if isinstance(raw_val, str) else raw_val
                            except Exception:
                                raw_bytes = b'\x00'
                            layers.append(scapy.Raw(load=raw_bytes))
                        else:
                            # Unknown template: try to eval template after substituting fixed values
                            try:
                                subs = {}
                                for k, v in fields.items():
                                    if v.get('mode') == 'fixed':
                                        subs[k] = v.get('value', '')
                                    else:
                                        subs[k] = "{" + k + "}"
                                part = tpl.format(**subs)
                                # attempt to eval with scapy context
                                ctx = {'Ether': scapy.Ether, 'Dot1Q': getattr(scapy, 'Dot1Q', None),
                                       'IP': scapy.IP, 'IPv6': getattr(scapy, 'IPv6', None),
                                       'UDP': scapy.UDP, 'TCP': getattr(scapy, 'TCP', None),
                                       'SCTP': getattr(scapy, 'SCTP', None),
                                       'GRE': getattr(scapy, 'GRE', None), 'VXLAN': getattr(scapy, 'VXLAN', None),
                                       'Raw': scapy.Raw}
                                pkt_layer = eval(part, {}, ctx)
                                layers.append(pkt_layer)
                            except Exception:
                                traceback.print_exc()
                                pass
                    if not layers:
                        eth_layer = scapy.Ether(
                            src=self.src_mac_le.text().strip() or '00:03:00:01:40:01',
                            dst=self.dst_mac_le.text().strip() or '00:02:00:03:04:02'
                        )
                        ip_layer = scapy.IP(
                            src=self.src_ip_le.text().strip() or '16.0.0.1',
                            dst=self.dst_ip_le.text().strip() or '48.0.0.1'
                        )
                        udp_layer = scapy.UDP(
                            sport=self.src_port_sb.value() or 1025,
                            dport=self.dst_port_sb.value() or 80
                        )
                        layers = [eth_layer, ip_layer, udp_layer]
                    pkt = layers[0]
                    for layer in layers[1:]:
                        pkt = pkt / layer
                    if sz:
                        current_size = len(bytes(pkt))
                        if sz > current_size:
                            pkt = pkt / scapy.Raw(load=b'X' * (sz - current_size))
                    return pkt
            except Exception as e:
                self.append_status(f"构建基础报文失败: {str(e)}", "错误")
                traceback.print_exc()
                return b'\x00' * (sz or 64)

        # Prepare VM (trex) or descriptive vm_desc
        vm = None
        vm_desc = {'vars': [], 'writes': []}
        if trex_ok:
            vm = STLVM()
        var_counter = 0

        # guess l4 proto
        l4_guess = (params.get('flow_type') or '').upper()
        if not l4_guess:
            for layer in comp:
                if layer.get('preset_id','').lower() == 'tcp':
                    l4_guess = 'TCP'; break
                if layer.get('preset_id','').lower() == 'udp':
                    l4_guess = 'UDP'; break
                if layer.get('preset_id','').lower() == 'sctp':
                    l4_guess = 'SCTP'; break
        if not l4_guess:
            l4_guess = 'UDP'

        # VM vars for composition fields (same as before)
        for li, layer in enumerate(comp):
            fields = layer.get('fields', {})
            for fname, fcfg in fields.items():
                mode = fcfg.get('mode','fixed')
                if mode == "fixed":
                    continue
                start = fcfg.get('start', fcfg.get('value',''))
                end = fcfg.get('end', start)
                step = int(fcfg.get('step', 1) or 1)
                is_ipv6 = False
                if isinstance(start, str):
                    if any(ip_keyword in fname.lower() for ip_keyword in ['ip', 'address']):
                        if ':' in start and start.count(':') >= 2:
                            is_ipv6 = True
                        try:
                            if ':' in start:
                                ipaddress.IPv6Address(start); is_ipv6 = True
                            else:
                                ipaddress.IPv4Address(start); is_ipv6 = False
                        except:
                            pass
                pkt_field = pkt_field_for(fname, l4_proto=l4_guess, is_ipv6=is_ipv6)
                if not pkt_field:
                    continue
                var_name = f"vm_{li}_{var_counter}_{fname}"
                var_counter += 1
                # similar handling as prior implementation
                if is_ipv6 or 'ip' in fname.lower():
                    try:
                        s_int = self._safe_ip_to_int(start, is_ipv6)
                        e_int = self._safe_ip_to_int(end, is_ipv6)
                        if s_int > e_int:
                            s_int, e_int = e_int, s_int
                        if trex_ok:
                            op = 'inc'
                            if mode == 'random':
                                op = 'rand'
                            elif mode == 'dec':
                                op = 'dec'
                            size = 16 if is_ipv6 else 4
                            try:
                                vm.var(name=var_name, min_value=s_int, max_value=e_int, size=size, op=op, step=step)
                                vm.write(fv_name=var_name, pkt_offset=pkt_field)
                            except Exception:
                                try:
                                    vm.var(var_name, s_int, e_int, size, op, step=step)
                                    vm.write(fv_name=var_name, pkt_offset=pkt_field)
                                except Exception as e2:
                                    self.append_status(f"VM变量创建失败: {str(e2)}", "错误")
                                    vm_desc['vars'].append(('ip', var_name, start, end, mode, step, pkt_field))
                                    vm_desc['writes'].append((var_name, pkt_field))
                        else:
                            vm_desc['vars'].append(('ip', var_name, start, end, mode, step))
                            vm_desc['writes'].append((var_name, pkt_field))
                    except Exception as e:
                        self.append_status(f"IP字段处理错误 {fname}: {str(e)}", "错误")
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
                elif 'mac' in fname.lower():
                    val = fcfg.get('value','')
                    if trex_ok and val:
                        try:
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

        # packet size handling: use new pkt_len param support
        sizes = self._compute_pkt_sizes_from_params(params)

        streams = []
        infos = []

        for sz in sizes:
            pkt_template = build_base_packet_for_size(sz)
            pkt_bytes = None
            if SCAPY_AVAILABLE and scapy is not None and pkt_template is not None:
                is_scapy_pkt = hasattr(pkt_template, 'summary') or hasattr(pkt_template, 'build') or hasattr(pkt_template, '__bytes__')
            else:
                is_scapy_pkt = False

            print(SCAPY_AVAILABLE)
            if not is_scapy_pkt:
                if isinstance(pkt_template, bytes):
                    pkt_bytes = pkt_template
                else:
                    pkt_bytes = b'\x00' * (sz or 64)

            if trex_ok:
                try:
                    if is_scapy_pkt:
                        try:
                            if var_counter:
                                pkt_builder = STLPktBuilder(pkt=pkt_template, vm=vm)
                            else:
                                pkt_builder = STLPktBuilder(pkt=pkt_template)
                        except Exception:
                            traceback.print_exc()
                            try:
                                pkt_builder = STLPktBuilder(pkt=bytes(pkt_template), vm=vm)
                            except Exception:
                                pkt_builder = STLPktBuilder(pkt=bytes(pkt_template) if hasattr(pkt_template, '__bytes__') else (pkt_bytes or b'\x00'*(sz or 64)), vm=vm)
                    else:
                        pkt_builder = STLPktBuilder(pkt=pkt_bytes or b'\x00'*(sz or 64), vm=vm)

                    # choose TX mode: if pps provided prefer pps (and do not use percentage concurrently)
                    tx_mode = None
                    if burst_count:
                        tx_mode = STLTXSingleBurst(total_pkts=burst_count, percentage=rate)
                    else:
                        if params.get('pps'):
                            try:
                                tx_mode = STLTXCont(pps=int(params.get('pps')))
                            except Exception:
                                tx_mode = STLTXCont(percentage=rate)
                        else:
                            tx_mode = STLTXCont(percentage=rate)

                    stream = STLStream(packet=pkt_builder, mode=tx_mode)

                    # attach metadata so controller.start_traffic (or other code) can respect run_mode/burst/run_duration
                    stream._tx_meta = {
                        'pps': params.get('pps'),
                        'rate_percent': params.get('rate_percent'),
                        'run_mode': run_mode,
                        'burst_count': burst_count,
                        'run_duration': run_duration
                    }

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

    # ---------------- Actions (save/add) ----------------
    def on_save_local(self):
        params, err = self._collect_params()
        if err:
            QMessageBox.warning(self, "保存失败", err)
            self.append_status(err, "错误")
            return

        # Use active port (view_port_sb) as target for creation by default
        try:
            active_port = int(self.view_port_sb.value())
        except Exception:
            active_port = None

        if active_port is None:
            tps = params.get('target_ports', [])
            if tps:
                active_port = tps[0]
                self.append_status(f"使用目标端口中的第一个端口 {active_port} 来创建 flow。", "警告")

        if active_port is None:
            QMessageBox.warning(self, "保存失败", "未指定要创建 flow 的端口（请选择查看端口或目标端口）。")
            return

        cfg = {
            'name': params['name'],
            'type': 'COMPOSED',
            'params': params,
            'tx_ports': [active_port],
            'rx_ports': [active_port]
        }
        try:
            # avoid duplicate by name on same port
            existing = self.controller.flow_configs.get(active_port, [])
            if any(conf.get('name') == cfg['name'] for conf in existing):
                self.append_status(f"端口 {active_port} 上已存在同名流 {cfg['name']}，跳过保存。", "警告")
            else:
                ok, msg = self.controller.add_flow_to_port(active_port, cfg)
                if ok:
                   # try:
                   #     self.controller.flow_configs.setdefault(active_port, []).append({
                   #         'name': cfg['name'],
                   #         'type': cfg['type'],
                   #         'params': cfg['params'],
                   #         'tx_ports': cfg['tx_ports'],
                   #         'rx_ports': cfg['rx_ports'],
                   #         'active': False,
                   #         'paused': False
                   #     })
                   # except Exception:
                   #     pass
                    self.append_status(f"已保存本地流配置: 端口 {active_port} ({msg})", "信息")
                else:
                    self.append_status(f"保存本地流失败: 端口 {active_port} ({msg})", "错误")
        except Exception as e:
            traceback.print_exc()
            self.append_status(f"调用控制器保存本地配置失败: {e}", "错误")

        # refresh flows UI
        if active_port is not None:
            try:
                self.view_port_sb.setValue(active_port)
            except Exception:
                pass
            self._selected_port_for_view = active_port
            self._refresh_flows_ui(active_port)

    def on_add_to_device(self):
        params, err = self._collect_params()
        if err:
            QMessageBox.warning(self, "参数错误", err)
            self.append_status(err, "错误")
            return

        # Use active port only (view_port_sb) to create flow
        try:
            active_port = int(self.view_port_sb.value())
        except Exception:
            tps = params.get('target_ports', [])
            active_port = tps[0] if tps else None
            if active_port is not None:
                self.append_status(f"使用目标端口中的第一个端口 {active_port} 来下发 flow。", "警告")

        if active_port is None:
            QMessageBox.warning(self, "错误", "没有可用的目标端口来下发流")
            return

        port = active_port
        try:
            if port not in self.controller.flow_configs:
                self.controller.flow_configs[port] = []
            flow_index = len(self.controller.flow_configs[port])
            streams_or_infos, err2 = self.create_streams_from_composition(params)
            if err2 is not None:
                self.append_status("无法直接下发到 T-Rex（或生成 streams 失败），已保存本地配置。详情见 vm_desc。", "警告")
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
                   # try:
                   #     self.controller.flow_configs.setdefault(port, []).append({
                   #         'name': cfg['name'],
                   #         'type': cfg['type'],
                   #         'params': cfg['params'],
                   #         'tx_ports': cfg['tx_ports'],
                   #         'rx_ports': cfg['rx_ports'],
                   #         'vm_desc': cfg.get('vm_desc'),
                   #         'active': False,
                   #         'paused': False
                   #     })
                   # except Exception:
                   #     pass
                    self.append_status(f"已保存本地流配置(回退): 端口 {port} ({msg})", "信息")
                else:
                    self.append_status(f"保存本地流失败(回退): 端口 {port} ({msg})", "错误")
                return

            # streams_or_infos is list of STLStream
            for s_i, stream in enumerate(streams_or_infos):
                base_pgid = (port + 1) * 1000
                pgid = base_pgid + flow_index + s_i + 1
                try:
                    if hasattr(stream, 'flow_stats') and stream.flow_stats is not None:
                        stream.flow_stats.pg_id = pgid
                except Exception:
                    pass
                if getattr(self.controller, 'is_connected', False):
                    try:
                        # If pps specified, don't pass percentage simultaneously
                        pps = params.get('pps', None)
                        rate_percent = params.get('rate_percent', None)
                        rate_to_pass = None if pps else rate_percent
                        #if pps:
                        #   pps = self.helper.format_pps(pps)
                        # Pass run parameters; controller.start_traffic should honor pps/run_mode/ burst_count / run_duration
                        if hasattr(self.controller, 'start_traffic'):
                            success, message = self.controller.start_traffic(
                                streams=[stream],
                                ports=[port],
                                rate_percent=rate_to_pass,
                                pps=pps,
                                duration=params.get('run_duration')
                            )
                            if not success:
                                self.append_status(f"下发并启动流警告: {message}", "警告")
                        else:
                            # fallback to client.add_streams (will not start automatically)
                            try:
                                self.controller.client.add_streams([stream], ports=[port])
                            except Exception:
                                traceback.print_exc()
                                self.append_status("向 T-Rex 下发流时出错，已保存本地配置", "错误")
                                self.on_save_local()
                                return
                    except Exception:
                        traceback.print_exc()
                        try:
                            self.controller.client.add_streams([stream], ports=[port])
                        except Exception:
                            traceback.print_exc()
                            self.append_status("向 T-Rex 下发流时出错，已保存本地配置", "错误")
                            self.on_save_local()
                            return
                # store metadata
                stored = {
                    'name': params['name'],
                    'type': 'COMPOSED',
                    'params': params,
                    'pgid': pgid,
                    'stream': stream,
                    'tx_ports': [port],
                    'rx_ports': [port],
                    'active': False,
                    'paused': False
                }
                self.controller.flow_configs[port].append(stored)
                self.append_status(f"已下发流到 T-Rex (port={port}, pgid={pgid})", "信息")
        except Exception as e:
            traceback.print_exc()
            self.append_status(f"端口 {port} 下发失败: {e}", "错误")
            QMessageBox.warning(self, "下发失败", f"端口 {port} 下发失败: {e}")

        # refresh flows UI
        if self._selected_port_for_view is not None:
            self._refresh_flows_ui(self._selected_port_for_view)

    def refresh_flow_list_for_port(self, port: int):
        try:
            self.view_port_sb.setValue(port)
            self._selected_port_for_view = port
            self._refresh_flows_ui(port)
        except Exception:
            pass

# trex_controller.py
# T-Rex 控制器（封装常用操作）
# 依赖 trex.stl.api 和 scapy，可在没有设备时回退为模拟实现

import time
import threading
from typing import List, Tuple, Dict, Any, Optional
import random
import os
import sys
import traceback

# try import trex API; if not available, we'll set client to None and use mocks
try:
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, parent_dir)
    import stl_path  # keeps trex path if needed
    from trex.stl.api import STLClient, STLStream, STLPktBuilder, STLTXCont, STLFlowStats
    TREX_AVAILABLE = True
except Exception:
    STLClient = None
    STLStream = None
    STLPktBuilder = None
    STLTXCont = None
    STLFlowStats = None
    TREX_AVAILABLE = False

# scapy for packet building / pcap writing
try:
    from scapy.all import Ether, IP, UDP, TCP, Dot1Q, ICMP, wrpcap
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

class TrexController:
    def __init__(self):
        self.client = None
        self.is_connected = False
        self.traffic_active = False
        self.flow_configs: Dict[int, List[Dict[str, Any]]] = {}
        self.capture_sessions: Dict[str, Dict[str, Any]] = {}
        self.capture_lock = threading.Lock()
        self.stats_thread: Optional[threading.Thread] = None
        self.stop_stats = False

    # ---------- connection ----------
    def connect(self, server: str = "127.0.0.1") -> Tuple[bool, str]:
        if not TREX_AVAILABLE:
            return False, "T-Rex Python bindings 未安装"
        try:
            self.client = STLClient(server=server)
            self.client.connect()
            self.is_connected = True
            return True, "连接成功"
        except Exception as e:
            return False, f"连接失败: {e}"

    def disconnect(self) -> Tuple[bool, str]:
        if not self.client:
            self.is_connected = False
            return True, "未连接"
        try:
            self.client.disconnect()
            self.is_connected = False
            return True, "断开成功"
        except Exception as e:
            return False, f"断开失败: {e}"

    def reset_ports(self, ports):
        """重置端口"""
        if not self.is_connected:
            return False, "未连接到 T-Rex 服务器"

        try:
            self.client.reset(ports=ports)
            return True, f"端口 {ports} 已重置"
        except Exception as e:
            return False, f"重置失败: {str(e)}"
    # ---------- traffic ----------
    def start_traffic(self, ports: List[int], streams: List, rate_percent: float, duration: int = 0) -> Tuple[bool, str]:
        if not self.is_connected or not self.client:
            return False, "未连接到T-Rex"
        try:
            if streams is not None:
                for p in ports:
                    self.client.add_streams(streams, ports=[p])
            if duration and duration > 0:
                self.client.start(ports=ports, mult=f"{rate_percent}%", duration=duration)
            else:
                self.client.start(ports=ports, mult=f"{rate_percent}%")
            print(f"ports={ports} rate_percent={rate_percent}")
            self.traffic_active = True
            return True, "流量已启动"
        except Exception as e:
            traceback.print_exc()
            return False, f"启动失败: {e}"

    def stop_traffic(self) -> Tuple[bool, str]:
        if not self.is_connected or not self.client:
            return False, "未连接"
        try:
            self.client.stop()
            try:
                self.client.wait_on_traffic()
            except Exception:
                pass
            self.traffic_active = False
            return True, "流量停止"
        except Exception as e:
            return False, f"停止失败: {e}"

    # ---------- stats ----------
    def get_stats(self) -> Optional[Dict]:
        if not self.is_connected or not self.client:
            # return empty dict for GUI convenience
            return {}
        try:
            return self.client.get_stats()
        except Exception:
            return {}

    def get_pgid_stats(self) -> Optional[Dict]:
        if not self.is_connected or not self.client:
            return {}
        try:
            return self.client.get_pgid_stats()
        except Exception:
            return {}

    def start_stats_monitor(self, callback, interval: float = 1.0):
        self.stop_stats = False
        def monitor():
            while not self.stop_stats:
                stats = self.get_stats()
                try:
                    callback(stats)
                except Exception:
                    pass
                time.sleep(interval)
        self.stats_thread = threading.Thread(target=monitor, daemon=True)
        self.stats_thread.start()

    def stop_stats_monitor(self):
        self.stop_stats = True
        if self.stats_thread and self.stats_thread.is_alive():
            self.stats_thread.join(timeout=1)

    # ---------- flow management ----------
    def add_flow_to_port(self, port: int, flow_config: Dict[str, Any]) -> Tuple[bool, str]:
        # store flow locally; add_streams should be invoked separately when stream object exists
        try:
            if port not in self.flow_configs:
                self.flow_configs[port] = []
            # assign pgid placeholder
            base = (port + 1) * 1000
            pgid = base + len(self.flow_configs[port]) + 1
            fc = dict(flow_config)
            fc['pgid'] = pgid
            self.flow_configs[port].append(fc)
            return True, f"保存本地配置 pgid={pgid}"
        except Exception as e:
            return False, f"添加失败: {e}"

    def remove_flow_from_port(self, port: int, index: int) -> Tuple[bool, str]:
        try:
            if port in self.flow_configs and 0 <= index < len(self.flow_configs[port]):
                self.flow_configs[port].pop(index)
                # optionally call client.remove_all_streams(ports=[port]) if desired
                return True, "已移除"
            return False, "流不存在"
        except Exception as e:
            return False, f"移除失败: {e}"

    def clear_port_flows(self, port: int) -> Tuple[bool, str]:
        try:
            self.flow_configs[port] = []
            if self.client:
                try:
                    self.client.remove_all_streams(ports=[port])
                except Exception:
                    pass
            return True, "已清空"
        except Exception as e:
            return False, f"清空失败: {e}"

    # ---------- capture ----------
    def start_capture(self, ports: List[int], limit: int = 1000, bpf_filter: str = '', mode: str = 'fixed') -> Tuple[bool, str]:
        # if trex client available, call its start_capture; otherwise mock session id and store
        if self.is_connected and self.client:
            try:
                capture_info = self.client.start_capture(rx_ports=ports, limit=limit, mode=mode, bpf_filter=bpf_filter)
                sid = f"capture_{int(time.time())}"
                self.capture_sessions[sid] = {'info': capture_info, 'ports': ports, 'active': True, 'packets': []}
                return True, sid
            except Exception as e:
                return False, f"启动捕获失败: {e}"
        else:
            # mock session
            sid = f"mock_capture_{int(time.time())}"
            self.capture_sessions[sid] = {'info': None, 'ports': ports, 'active': True, 'packets': [], 'mock': True}
            return True, sid

    def stop_capture(self, session_id: str, output_file: str = None) -> Tuple[bool, Any]:
        if session_id not in self.capture_sessions:
            return False, "会话不存在"
        sess = self.capture_sessions[session_id]
        if self.is_connected and self.client and sess.get('info'):
            try:
                if output_file:
                    pkts = self.client.stop_capture(sess['info']['id'], output_file)
                else:
                    pkts = []
                    self.client.stop_capture(sess['info']['id'], output=pkts)
                sess['active'] = False
                sess['packets'] = pkts
                return True, pkts
            except Exception as e:
                return False, f"停止捕获失败: {e}"
        else:
            # produce mock packets
            sess['active'] = False
            mock_pkts = [b'\x00' * (64 + (i % 100)) for i in range(10)]
            sess['packets'] = mock_pkts
            return True, mock_pkts

    def get_captured_packets(self, session_id: str) -> Tuple[bool, Any]:
        if session_id not in self.capture_sessions:
            return False, "会话不存在"
        sess = self.capture_sessions[session_id]
        return True, list(sess.get('packets', []))

    # ---------- utility ----------
    @staticmethod
    def format_bps(bps: float) -> str:
        if bps >= 1e9:
            return f"{bps/1e9:.2f} Gbps"
        if bps >= 1e6:
            return f"{bps/1e6:.2f} Mbps"
        if bps >= 1e3:
            return f"{bps/1e3:.2f} Kbps"
        return f"{bps:.0f} bps"

    @staticmethod
    def format_pps(pps: float) -> str:
        if pps >= 1e6:
            return f"{pps/1e6:.2f} Mpps"
        if pps >= 1e3:
            return f"{pps/1e3:.2f} Kpps"
        return f"{pps:.0f} pps"

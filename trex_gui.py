# trex_gui.py
# Main GUI assembly which composes the smaller tab modules.
import sys
import traceback
from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget, QVBoxLayout, QWidget
from PyQt5.QtCore import pyqtSignal

from trex_controller import TrexController
from modules.connection_tab import ConnectionTab
from modules.traffic_tab import TrafficTab
from modules.rfc2544_tab import Rfc2544Tab
from modules.stats_tab import StatsTab
from modules.log_tab import LogTab
from modules.capture_tab import CaptureTab

# Import T-Rex STL stream/packet builder classes for real stream creation
try:
    from trex.stl.api import STLStream, STLPktBuilder, STLTXCont, STLFlowStats
    TREX_STL_AVAILABLE = True
except Exception:
    STLStream = STLPktBuilder = STLTXCont = STLFlowStats = None
    TREX_STL_AVAILABLE = False

class TrexGUI(QMainWindow):
    """Main application window that composes modular tabs."""
    # Expose some signals for child modules if needed
    log_signal = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.controller = TrexController()
        self.setWindowTitle("T-Rex 流量测试系统 (模块化)")
        self.resize(1200, 800)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout()
        central.setLayout(layout)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # Status bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("就绪")

        # Create modular tabs and keep references
        self.connection_tab = ConnectionTab(self.controller, parent=self)
        self.flow_editor_tab = TrafficTab(self.controller, parent=self)
        self.capture_tab = CaptureTab(self.controller, parent=self)
        self.stats_tab = StatsTab(self.controller, parent=self)
        self.logs_tab = LogTab(parent=self)

        # Add tabs to QTabWidget
        self.tabs.addTab(self.connection_tab, "连接配置")
        self.tabs.addTab(self.flow_editor_tab, "流量配置 / RFC2544")
        self.tabs.addTab(self.stats_tab, "统计信息")
        self.tabs.addTab(self.capture_tab, "数据包抓取")
        self.tabs.addTab(self.logs_tab, "日志")

        # wire up basic interactions
        # when connection changes, update other tabs' UI state
        # child tabs will call parent.log_message to write logs
        # enable capture start button when connected
        self.connection_tab.connect_btn.clicked.connect(self._on_connected)
        self.connection_tab.disconnect_btn.clicked.connect(self._on_disconnected)

    def _on_connected(self):
        # update capture tab and stats tab UI states
        self.capture_tab.update_capture_ui_state()
        self.stats_tab.parent = self
        self.flow_editor_tab.parent = self
        # enable capture start
        self.capture_tab.start_capture_btn.setEnabled(True)
        self.flow_editor_tab.start_test_btn.setEnabled(True)
        self.logs_tab.add_log_entry("已连接到 T-Rex 服务器", "信息")

    def _on_disconnected(self):
        self.capture_tab.update_capture_ui_state()
        self.flow_editor_tab.start_test_btn.setEnabled(False)
        self.logs_tab.add_log_entry("已断开 T-Rex 服务器", "信息")

    def log_message(self, message: str, level: str = "信息"):
        """Central log dispatcher called by submodules."""
        self.status_bar.showMessage(message, 5000)
        if hasattr(self, 'logs_tab'):
            try:
                self.logs_tab.add_log_entry(message, level)
            except Exception:
                pass
        print(f"[{level}] {message}")

    def create_stream_with_frame_size(self, frame_size):
        """
        Real implementation: create an STLStream based on the current flow editor UI
        configuration and the TrexController's flow templates/packet builders.
        """
        try:
            if not hasattr(self, 'flow_editor_tab') or self.flow_editor_tab is None:
                self.log_message("Flow editor not ready", "错误")
                return None

            if not hasattr(self.flow_editor_tab, 'get_flow_config_from_ui'):
                self.log_message("Flow editor does not expose get_flow_config_from_ui()", "错误")
                return None

            cfg = self.flow_editor_tab.get_flow_config_from_ui()
            cfg['pkt_size'] = frame_size

            flow_type = cfg.get('type', 'UDP')
            template = self.controller.create_flow_template(flow_type)
            if not template:
                self.log_message(f"不支持的流量类型: {flow_type}", "错误")
                return None

            params = template.get('default_params', {}).copy()
            params.update(cfg.get('params', {}))
            for k in ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'src_mac', 'dst_mac',
                      'vlan_enabled', 'vlan_id', 'vlan_prio', 'pkt_size', 'rate',
                      'random_pkt_size', 'pkt_size_min', 'pkt_size_max',
                      'random_src_ip', 'sip_range_start', 'sip_range_end',
                      'random_dst_ip', 'dip_range_start', 'dip_range_end',
                      'random_src_port', 'sport_range_start', 'sport_range_end',
                      'random_dst_port', 'dport_range_start', 'dport_range_end']:
                if k in cfg:
                    params[k] = cfg[k]

            params['pkt_size'] = frame_size

            pkt_obj = template['packet'](params)

            if TREX_STL_AVAILABLE and isinstance(pkt_obj, STLPktBuilder):
                pkt_builder = pkt_obj
            else:
                if TREX_STL_AVAILABLE:
                    try:
                        pkt_builder = STLPktBuilder(pkt=pkt_obj)
                    except Exception as e:
                        self.log_message(f"无法将数据包封装为 STLPktBuilder: {e}", "错误")
                        return None
                else:
                    self.log_message("T-Rex STL bindings not available", "错误")
                    return None

            percentage = params.get('rate', cfg.get('rate', 50.0))
            try:
                stream = STLStream(
                    packet=pkt_builder,
                    mode=STLTXCont(percentage=percentage),
                    flow_stats=STLFlowStats(pg_id=1)
                )
                self.log_message(f"已创建流: 类型={flow_type}, 帧大小={frame_size}, 速率={percentage}%", "信息")
                return stream
            except Exception as e:
                self.log_message(f"创建 STLStream 失败: {e}", "错误")
                return None

        except Exception as e:
            self.log_message(f"create_stream_with_frame_size 异常: {e}", "错误")
            traceback.print_exc()
            return None

    def _create_stream_with_frame_size_stub(self, frame_size):
        return self.create_stream_with_frame_size(frame_size)

    def closeEvent(self, event):
        try:
            self.controller.stop_stats_monitor()
            self.controller.stop_traffic()
            self.controller.disconnect()
        except Exception:
            pass
        event.accept()

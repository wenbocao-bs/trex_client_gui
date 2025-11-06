
"""
T-Rex 流量测试系统工具函数模块
包含格式化函数、类型转换、数据解析等通用工具
"""
import time
import struct
import random
from typing import Union, List, Dict, Any
from PyQt5.QtGui import QColor
from PyQt5.QtCore import Qt


class HelperFunctions:
    """工具函数类"""

    @staticmethod
    def format_bps(bps: float) -> str:
        """格式化比特率显示"""
        if bps >= 1e9:
            return f"{bps/1e9:.2f} Gbps"
        elif bps >= 1e6:
            return f"{bps/1e6:.2f} Mbps"
        elif bps >= 1e3:
            return f"{bps/1e3:.2f} Kbps"
        return f"{bps:.0f} bps"

    @staticmethod
    def format_pps(pps: float) -> str:
        """格式化PPS（每秒包数）显示"""
        if pps >= 1e9:
            return f"{pps/1e9:.2f}gpps"
        elif pps >= 1e6:
            return f"{pps/1e6:.2f}mpps"
        elif pps >= 1e3:
            return f"{pps/1e3:.2f}kpps"
        return f"{pps:.0f}pps"

    @staticmethod
    def format_bytes(bytes_val: float) -> str:
        """格式化字节数显示"""
        if bytes_val >= 1e9:
            return f"{bytes_val/1e9:.2f} GB"
        elif bytes_val >= 1e6:
            return f"{bytes_val/1e6:.2f} MB"
        elif bytes_val >= 1e3:
            return f"{bytes_val/1e3:.2f} KB"
        return f"{bytes_val} B"

    @staticmethod
    def ip_to_int(ip: str) -> int:
        """将IP地址转换为整数"""
        return sum(int(octet) << (24 - i * 8) for i, octet in enumerate(ip.split('.')))

    @staticmethod
    def int_to_ip(ip_int: int) -> str:
        """将整数转换为IP地址"""
        return '.'.join(str((ip_int >> (24 - i * 8)) & 0xFF) for i in range(4))

    @staticmethod
    def generate_mock_packets(count: int) -> List[bytes]:
        """生成模拟数据包（用于测试）"""
        packets = []
        for i in range(count):
            # 生成简单的以太网/IP包
            src_mac = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
            dst_mac = bytes([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee])
            eth_type = b'\x08\x00'  # IPv4

            # IP头
            ip_header = struct.pack('!BBHHHBBH4s4s',
                                0x45, 0, 20 + 20,  # Version/IHL, ToS, Total Length
                                random.randint(1, 1000), 0, 64, 6, 0,  # Identification, Flags, TTL, Protocol, Checksum
                                bytes([192, 168, 1, random.randint(1, 254)]),  # Source IP
                                bytes([192, 168, 1, random.randint(1, 254)])   # Dest IP
                                )

            # TCP头（简化）
            tcp_header = struct.pack('!HHLLBBHHH',
                                random.randint(1024, 65535), 80,  # Source port, Dest port
                                random.randint(1, 1000000), 0,  # Sequence number, Ack number
                                5 << 4, 0x10, 8192, 0, 0)  # Data offset, Flags, Window, Checksum, Urgent

            packet = dst_mac + src_mac + eth_type + ip_header + tcp_header
            packets.append(packet)

        return packets

    @staticmethod
    def get_color_for_value(value: float, thresholds: Dict[str, float]) -> QColor:
        """根据数值和阈值返回对应的颜色"""
        if value > thresholds.get('critical', 1.0):
            return QColor(255, 0, 0)  # 红色 - 严重
        elif value > thresholds.get('warning', 0.1):
            return QColor(255, 165, 0)  # 橙色 - 警告
        elif value > thresholds.get('notice', 0.01):
            return QColor(255, 255, 0)  # 黄色 - 注意
        else:
            return QColor(0, 255, 0)  # 绿色 - 正常

    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """验证IP地址格式"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit() or not 0 <= int(part) <= 255:
                return False
        return True

    @staticmethod
    def validate_mac_address(mac: str) -> bool:
        """验证MAC地址格式"""
        parts = mac.split(':')
        if len(parts) != 6:
            return False
        for part in parts:
            if len(part) != 2 or not all(c in '0123456789ABCDEFabcdef' for c in part):
                return False
        return True

    @staticmethod
    def calculate_loss_rate(tx_packets: int, rx_packets: int) -> float:
        """计算丢包率"""
        if tx_packets == 0:
            return 0.0
        return max(0.0, (tx_packets - rx_packets) / tx_packets * 100)

    @staticmethod
    def calculate_throughput(packets: int, duration: float, packet_size: int) -> float:
        """计算吞吐量（bps）"""
        if duration == 0:
            return 0.0
        return (packets * packet_size * 8) / duration

    @staticmethod
    def timestamp_to_str(timestamp: float) -> str:
        """将时间戳转换为可读字符串"""
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))

    @staticmethod
    def format_duration(seconds: float) -> str:
        """格式化持续时间显示"""
        if seconds < 60:
            return f"{seconds:.2f}秒"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.2f}分钟"
        else:
            hours = seconds / 3600
            return f"{hours:.2f}小时"

    @staticmethod
    def safe_get(dictionary: Dict, key: str, default: Any = None) -> Any:
        """安全获取字典值，避免KeyError"""
        try:
            return dictionary.get(key, default)
        except (KeyError, AttributeError):
            return default

    @staticmethod
    def parse_port_string(port_str: str) -> List[int]:
        """解析端口字符串（如 "0,1,2"）为整数列表"""
        try:
            return [int(p.strip()) for p in port_str.split(',') if p.strip().isdigit()]
        except (ValueError, AttributeError):
            return []

    @staticmethod
    def create_port_string(ports: List[int]) -> str:
        """将端口列表转换为字符串"""
        return ','.join(map(str, ports))

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


class PacketParser:
    """数据包解析工具类"""

    @staticmethod
    def parse_ethernet_header(packet_data: bytes) -> Dict[str, str]:
        """解析以太网帧头"""
        if len(packet_data) < 14:
            return {}

        dst_mac = packet_data[0:6].hex(':')
        src_mac = packet_data[6:12].hex(':')
        eth_type = packet_data[12:14].hex()

        return {
            'dst_mac': dst_mac,
            'src_mac': src_mac,
            'eth_type': eth_type
        }

    @staticmethod
    def parse_ip_header(packet_data: bytes) -> Dict[str, Any]:
        """解析IP头"""
        if len(packet_data) < 34:  # 以太网头14字节 + IP头至少20字节
            return {}

        ip_header = packet_data[14:34]
        version = (ip_header[0] >> 4) & 0x0F
        header_length = (ip_header[0] & 0x0F) * 4
        protocol = ip_header[9]
        src_ip = '.'.join(str(b) for b in ip_header[12:16])
        dst_ip = '.'.join(str(b) for b in ip_header[16:20])

        return {
            'version': version,
            'header_length': header_length,
            'protocol': protocol,
            'src_ip': src_ip,
            'dst_ip': dst_ip
        }

    @staticmethod
    def get_packet_protocol(packet_data: bytes) -> str:
        """获取数据包协议类型"""
        try:
            ip_info = PacketParser.parse_ip_header(packet_data)
            protocol_map = {
                1: 'ICMP',
                6: 'TCP',
                17: 'UDP'
            }
            return protocol_map.get(ip_info.get('protocol', 0), 'Unknown')
        except:
            return 'Unknown'


class StatisticsCalculator:
    """统计计算工具类"""

    @staticmethod
    def calculate_average(values: List[float]) -> float:
        """计算平均值"""
        if not values:
            return 0.0
        return sum(values) / len(values)

    @staticmethod
    def calculate_std_dev(values: List[float]) -> float:
        """计算标准差"""
        if len(values) < 2:
            return 0.0
        mean = StatisticsCalculator.calculate_average(values)
        variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
        return variance ** 0.5

    @staticmethod
    def calculate_percentile(values: List[float], percentile: int) -> float:
        """计算百分位数"""
        if not values:
            return 0.0
        sorted_values = sorted(values)
        index = (percentile / 100) * (len(sorted_values) - 1)

        if index.is_integer():
            return sorted_values[int(index)]
        else:
            lower = sorted_values[int(index)]
            upper = sorted_values[int(index) + 1]
            return lower + (upper - lower) * (index - int(index))

    @staticmethod
    def calculate_jitter(latency_values: List[float]) -> float:
        """计算时延抖动"""
        if len(latency_values) < 2:
            return 0.0

        jitter_sum = 0
        for i in range(1, len(latency_values)):
            jitter_sum += abs(latency_values[i] - latency_values[i-1])

        return jitter_sum / (len(latency_values) - 1)

# 创建全局实例
helper = HelperFunctions()
packet_parser = PacketParser()
stats_calculator = StatisticsCalculator()

# 向后兼容的别名
format_bps = helper.format_bps
format_pps = helper.format_pps
format_bytes = helper.format_bytes

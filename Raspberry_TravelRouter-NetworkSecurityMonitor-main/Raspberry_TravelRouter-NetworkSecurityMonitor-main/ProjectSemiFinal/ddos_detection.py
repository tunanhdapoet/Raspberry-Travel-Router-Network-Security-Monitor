import pandas as pd
from datetime import datetime, timedelta
import sqlite3
import numpy as np
from collections import defaultdict
import threading
import time
import logging

# Thiết lập logging
logging.basicConfig(
    filename='static/ddos_alerts.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class DDoSDetector:
    def __init__(self):
        # Các ngưỡng phát hiện DDoS
        self.PACKET_THRESHOLD = 1000  # Số lượng gói tin/giây
        self.CONNECTION_THRESHOLD = 100  # Số lượng kết nối đồng thời
        self.TIME_WINDOW = 60  # Cửa sổ thời gian (giây)
        self.BURST_THRESHOLD = 5000  # Ngưỡng burst traffic
        
        # Lưu trữ thống kê
        self.ip_stats = defaultdict(lambda: {
            'packet_count': 0,
            'last_seen': datetime.now(),
            'connections': set(),
            'bytes_total': 0
        })
        
        # Danh sách IP đang bị chặn
        self.blocked_ips = set()
        
        # Lock để thread-safe
        self.stats_lock = threading.Lock()

    def get_recent_traffic(self):
        """Lấy dữ liệu traffic gần đây từ database"""
        try:
            conn = sqlite3.connect('network_data.db')
            query = """
            SELECT timestamp, src_ip, dst_ip, protocol, length, src_port, dst_port
            FROM network_traffic
            WHERE timestamp >= datetime('now', '-1 minute')
            """
            df = pd.read_sql_query(query, conn)
            conn.close()
            return df
        except Exception as e:
            logging.error(f"Error getting traffic data: {e}")
            return pd.DataFrame()

    def analyze_traffic_patterns(self, df):
        """Phân tích mẫu traffic để phát hiện DDoS"""
        if df.empty:
            return
        
        current_time = datetime.now()
        alerts = []
        
        with self.stats_lock:
            # Phân tích theo source IP
            for src_ip in df['src_ip'].unique():
                ip_data = df[df['src_ip'] == src_ip]
                
                # Tính toán các metric
                packets_per_second = len(ip_data) / self.TIME_WINDOW
                unique_connections = len(set(zip(ip_data['dst_ip'], ip_data['dst_port'])))
                total_bytes = ip_data['length'].sum()
                
                # Cập nhật thống kê
                self.ip_stats[src_ip]['packet_count'] = packets_per_second
                self.ip_stats[src_ip]['connections'].update(
                    set(zip(ip_data['dst_ip'], ip_data['dst_port']))
                )
                self.ip_stats[src_ip]['bytes_total'] = total_bytes
                self.ip_stats[src_ip]['last_seen'] = current_time
                
                # Kiểm tra các dấu hiệu DDoS
                if self._check_ddos_indicators(src_ip):
                    alert_msg = self._generate_alert(src_ip)
                    alerts.append(alert_msg)
                    self.blocked_ips.add(src_ip)
        
        return alerts

    def _check_ddos_indicators(self, ip):
        """Kiểm tra các dấu hiệu DDoS cho một IP"""
        stats = self.ip_stats[ip]
        
        # Kiểm tra các điều kiện
        high_packet_rate = stats['packet_count'] > self.PACKET_THRESHOLD
        many_connections = len(stats['connections']) > self.CONNECTION_THRESHOLD
        high_bandwidth = stats['bytes_total'] > self.BURST_THRESHOLD
        
        # Trả về True nếu thỏa mãn ít nhất 2 điều kiện
        return sum([high_packet_rate, many_connections, high_bandwidth]) >= 2

    def _generate_alert(self, ip):
        """Tạo thông báo cảnh báo chi tiết"""
        stats = self.ip_stats[ip]
        alert = f"""
DOS ATTACK DETECTED!
Source IP: {ip}
Time: {datetime.now()}
Indicators:
- Packets/sec: {stats['packet_count']:.2f}
- Unique connections: {len(stats['connections'])}
- Total bandwidth: {stats['bytes_total']/1024:.2f} KB
"""
        logging.warning(alert)
        return alert

    def cleanup_old_stats(self):
        """Xóa thống kê cũ"""
        current_time = datetime.now()
        with self.stats_lock:
            for ip in list(self.ip_stats.keys()):
                if (current_time - self.ip_stats[ip]['last_seen']).seconds > self.TIME_WINDOW:
                    del self.ip_stats[ip]


    def start_ddos_monitoring():
        """Khởi động monitoring trong thread riêng"""
        detector = DDoSDetector()

        def monitoring_task():
            while True:
                try:
                    # Lấy và phân tích traffic
                    df = detector.get_recent_traffic()
                    alerts = detector.analyze_traffic_patterns(df)

                    # Ghi alerts vào file
                    if alerts:
                        with open('static/ddos_alerts.txt', 'w') as f:
                            for alert in alerts:
                                f.write(f"{alert}\n{'=' * 50}\n")

                    # Dọn dẹp thống kê cũ
                    detector.cleanup_old_stats()

                    time.sleep(5)

                except Exception as e:
                    logging.error(f"Error in DoS monitoring: {e}")
                    time.sleep(5)

        # Khởi động thread monitoring
        monitor_thread = threading.Thread(target=monitoring_task, daemon=True)
        monitor_thread.start()
        return detector

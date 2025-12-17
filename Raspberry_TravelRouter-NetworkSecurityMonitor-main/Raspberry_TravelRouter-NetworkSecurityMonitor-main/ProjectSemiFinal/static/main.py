from flask import Flask, render_template, jsonify, request
import os
from log_analysis import analyze_traffic, detect_potential_scans
from database import init_db
from scapy.all import sniff
import threading
from datetime import datetime
from ip_blocker import ip_blocker
import sqlite3
import re
import subprocess
from ddos_detection import DDoSDetector
import pandas as pd
app = Flask(__name__)
ddos_detector = DDoSDetector()

@app.template_filter('regex_findall')
def regex_findall(value, pattern):
    return re.findall(pattern, value)

def check_sudo_access():
    try:
        subprocess.run(["sudo", "-n", "true"], check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def generate_traffic_stats(df):
    stats = [
        f"Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total Packets: {len(df)}",
        f"Unique Source IPs: {df['src_ip'].nunique()}",
        f"Unique Destination IPs: {df['dst_ip'].nunique()}",
        f"Average Packet Size: {df['length'].mean():.2f} bytes",
        f"Most Common Protocol: {df['protocol'].mode().iloc[0]}",
        "\nTop 5 Source IPs:",
        df['src_ip'].value_counts().head().to_string(),
        "\nProtocol Distribution:",
        df['protocol'].value_counts().to_string()
    ]

    with open('static/traffic_stats.txt', 'w') as f:
        f.write('\n'.join(stats))

def get_data_from_db():
    try:
        conn = sqlite3.connect('network_data.db')
        query = """
        SELECT timestamp, src_ip, dst_ip, protocol, length, src_port, dst_port
        FROM network_traffic 
        WHERE timestamp >= datetime('now', '-5 minute')
        ORDER BY timestamp DESC
        """
        df = pd.read_sql_query(query, conn)
        conn.close()

        # Chuyển đổi timestamp thành datetime
        df['timestamp'] = pd.to_datetime(df['timestamp'])

        return df
    except Exception as e:
        print(f"Error getting data from database: {e}")
        return pd.DataFrame()

def ensure_static_directory():
    """Đảm bảo thư mục static tồn tại"""
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
    if not os.path.exists(static_dir):
        os.makedirs(static_dir)
    return static_dir

def read_file_content(filename):
    """Đọc nội dung file an toàn"""
    try:
        file_path = os.path.join(app.static_folder, filename)
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                return f.read()
        return "File not found"
    except Exception as e:
        return f"Error reading file: {str(e)}"

def packet_callback(packet):
    """Callback function để xử lý gói tin"""
    from database import insert_traffic_data
    from scapy.layers.inet import IP, TCP, UDP
    
    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            length = len(packet)
            
            if TCP in packet:
                protocol = 'TCP'
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                protocol = 'UDP'
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            else:
                protocol = 'Other'
                src_port = None
                dst_port = None
                
            insert_traffic_data(src_ip, dst_ip, protocol, length, src_port, dst_port)
    except Exception as e:
        print(f"Error processing packet: {str(e)}")

def start_packet_capture():
    """Bắt đầu bắt gói tin trong thread riêng"""
    try:
        sniff(prn=packet_callback, store=0)
    except Exception as e:
        print(f"Error in packet capture: {str(e)}")

def analyze_traffic():
    df = get_data_from_db()

    if df.empty:
        print("No data available for analysis")
        # Tạo file thống kê trống
        with open('static/traffic_stats.txt', 'w') as f:
            f.write("No traffic data available for analysis")
        with open('static/nmap_detections.txt', 'w') as f:
            f.write("No data available for scan detection")
        with open('static/ddos_detections.txt', 'w') as f:
            f.write("No data available for DDoS detection")
        return

    # Phân tích traffic chung
    generate_traffic_stats(df)

    # Phát hiện quét Nmap
    detect_potential_scans(df)

    # Phát hiện DDoS
    ddos_alerts = ddos_detector.analyze_traffic_patterns(df)
    with open('static/ddos_detections.txt', 'w') as f:
        if ddos_alerts:
            f.write('\n'.join(ddos_alerts))
        else:
            f.write("No DDoS attacks detected.")


@app.route('/')
def index():
    """Trang chủ"""
    try:
        ensure_static_directory()
        analyze_traffic()
        
        nmap_detections = read_file_content('nmap_detections.txt')
        traffic_stats = read_file_content('traffic_stats.txt')
        ddos_detections = read_file_content('ddos_detections.txt')
        
        return render_template('index.html',
                             nmap_detections=nmap_detections,
                             traffic_stats=traffic_stats,
                             ddos_detections=ddos_detections)
    except Exception as e:
        return f"Error: {str(e)}", 500


@app.route('/api/traffic/latest')
def get_latest_traffic():
    """API endpoint để lấy dữ liệu traffic mới nhất"""
    try:
        conn = sqlite3.connect('network_data.db')
        cursor = conn.cursor()

        # Lấy thống kê tổng quát
        cursor.execute('SELECT COUNT(*) FROM network_traffic')
        total_packets = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(DISTINCT src_ip) FROM network_traffic')
        unique_ips = cursor.fetchone()[0]

        cursor.execute('SELECT AVG(length) FROM network_traffic')
        avg_packet_size = cursor.fetchone()[0] or 0

        # Lấy dữ liệu traffic gần nhất
        cursor.execute('''
        SELECT timestamp, src_ip, dst_ip, protocol, length
        FROM network_traffic
        ORDER BY timestamp DESC
        LIMIT 100
        ''')

        traffic_data = cursor.fetchall()
        conn.close()

        # Định dạng dữ liệu trả về
        formatted_data = [{
            'timestamp': row[0],
            'src_ip': row[1],
            'dst_ip': row[2],
            'protocol': row[3],
            'length': row[4],
            'stats': {
                'total_packets': total_packets,
                'unique_ips': unique_ips,
                'avg_packet_size': float(avg_packet_size)
            } if idx == 0 else None  # Chỉ gửi stats với bản ghi đầu tiên
        } for idx, row in enumerate(traffic_data)]

        return jsonify(formatted_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats')
def get_stats():
    """API endpoint để lấy thống kê"""
    try:
        conn = sqlite3.connect('network_data.db')
        cursor = conn.cursor()

        cursor.execute('SELECT COUNT(*) FROM network_traffic')
        total_packets = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(DISTINCT src_ip) FROM network_traffic')
        unique_src_ips = cursor.fetchone()[0]

        cursor.execute('SELECT AVG(length) FROM network_traffic')
        avg_packet_size = cursor.fetchone()[0] or 0

        cursor.execute('''
        SELECT protocol, COUNT(*) as count
        FROM network_traffic
        GROUP BY protocol
        ''')
        protocol_dist = dict(cursor.fetchall())

        conn.close()

        return jsonify({
            'total_packets': total_packets,
            'unique_source_ips': unique_src_ips,
            'avg_packet_size': round(avg_packet_size, 2),
            'protocol_distribution': protocol_dist,
            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/block-ip', methods=['POST'])
def block_ip():
    try:
        data = request.get_json()
        ip = data.get('ip')
        duration = data.get('duration', 2)  # mặc định 2 phút
        reason = data.get('reason', 'Manual block')
        
        if not ip:
            return jsonify({'error': 'IP address required'}), 400
            
        ip_blocker.block_ip(ip, duration, reason, manual=True)
        return jsonify({'message': f'IP {ip} blocked successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/unblock-ip', methods=['POST'])
def unblock_ip():
    try:
        data = request.get_json()
        ip = data.get('ip')
        
        if not ip:
            return jsonify({'error': 'IP address required'}), 400
            
        if ip_blocker.unblock_ip(ip):
            return jsonify({'message': f'IP {ip} unblocked successfully'})
        return jsonify({'error': 'IP not found in blocked list'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/blocked-ips')
def get_blocked_ips():
    try:
        return jsonify(ip_blocker.get_blocked_ips())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def initialize_app():
    """Khởi tạo ứng dụng"""
    try:
        if not check_sudo_access():
            print("WARNING: This application requires sudo privileges to manage iptables rules.")
            print("Please run the application with sudo or configure sudoers file.")
            return
        # Khởi tạo database
        init_db()
        
        # Khởi tạo thư mục static
        ensure_static_directory()
        
        # Bắt đầu thread bắt gói tin
        capture_thread = threading.Thread(target=start_packet_capture, daemon=True)
        capture_thread.start()
        print("Application initialized successfully")
    except Exception as e:
        print(f"Error initializing application: {str(e)}")

if __name__ == '__main__':
    initialize_app()
    app.run(debug=True, host='0.0.0.0', port=5000)



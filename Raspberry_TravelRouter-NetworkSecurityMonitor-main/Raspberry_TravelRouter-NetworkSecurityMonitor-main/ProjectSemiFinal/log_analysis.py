import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import os
import numpy as np
import sqlite3
plt.switch_backend('Agg')

def get_data_from_db():
    """Đọc dữ liệu từ SQLite database"""
    try:
        conn = sqlite3.connect('network_data.db')
        query = """
        SELECT timestamp, src_ip, dst_ip, protocol, length, src_port, dst_port
        FROM network_traffic 
        ORDER BY timestamp DESC 
        LIMIT 10000
        """
        df = pd.read_sql_query(query, conn)
        conn.close()
        return df
    except Exception as e:
        print(f"Error reading from database: {e}")
        return pd.DataFrame()

def analyze_traffic():
    """Phân tích traffic và tạo báo cáo"""
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
    
    # Chuyển đổi timestamp thành datetime
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    try:
        # Phân tích và tạo biểu đồ
        plt.figure(figsize=(15, 10))
        
        # 1. Traffic theo thời gian
        plt.subplot(2, 2, 1)
        if not df.empty and len(df['timestamp'].unique()) > 1:
            df.groupby(df['timestamp'].dt.hour)['length'].mean().plot(kind='bar')
            plt.title('Average Traffic by Hour')
            plt.xlabel('Hour')
            plt.ylabel('Average Packet Size')
        else:
            plt.text(0.5, 0.5, 'Not enough data', ha='center', va='center')
        
        # 2. Protocol distribution
        plt.subplot(2, 2, 2)
        if not df.empty:
            plt.subplot(2, 2, 1)
            protocol_counts = df['protocol'].value_counts()
            plt.pie(protocol_counts.values, labels=protocol_counts.index, autopct='%1.1f%%')
            plt.title('Protocol Distribution')
        
        # 3. Top source IPs
        plt.subplot(2, 2, 3)
        if not df.empty:
            df['src_ip'].value_counts().head(10).plot(kind='bar')
            plt.title('Top 10 Source IPs')
            plt.xticks(rotation=45)
        else:
            plt.text(0.5, 0.5, 'Not enough data', ha='center', va='center')
        
        # 4. Packet size distribution
        plt.subplot(2, 2, 4)
        if not df.empty:
            df['length'].hist(bins=50)
            plt.title('Packet Size Distribution')
            plt.xlabel('Packet Size')
            plt.ylabel('Frequency')
        else:
            plt.text(0.5, 0.5, 'Not enough data', ha='center', va='center')
        
        plt.tight_layout()
        plt.savefig('static/traffic_analysis.png')
        plt.close()
    except Exception as e:
        print(f"Error creating plots: {e}")
        plt.figure(figsize=(10, 6))
        plt.text(0.5, 0.5, f'Error creating analysis plots: {str(e)}', 
                ha='center', va='center', wrap=True)
        plt.savefig('static/traffic_analysis.png')
        plt.close()
    
    # Tạo báo cáo thống kê
    try:
        stats = [
            f"Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Total Packets: {len(df)}",
            f"Unique Source IPs: {df['src_ip'].nunique()}",
            f"Unique Destination IPs: {df['dst_ip'].nunique()}",
            f"Average Packet Size: {df['length'].mean():.2f} bytes" if not df.empty else "Average Packet Size: N/A",
            f"Most Common Protocol: {df['protocol'].mode().iloc[0]}" if not df.empty else "Most Common Protocol: N/A",
            "\nTop 5 Source IPs:",
            df['src_ip'].value_counts().head().to_string() if not df.empty else "No data",
            "\nProtocol Distribution:",
            df['protocol'].value_counts().to_string() if not df.empty else "No data"
        ]
        
        with open('static/traffic_stats.txt', 'w') as f:
            f.write('\n'.join(stats))
    except Exception as e:
        with open('static/traffic_stats.txt', 'w') as f:
            f.write(f"Error generating statistics: {str(e)}")
    
    # Phát hiện quét Nmap và DDoS
    detect_potential_scans(df)
    detect_ddos_attacks(df)

def detect_potential_scans(df):
    """Phát hiện các dấu hiệu của quét Nmap"""
    if df.empty:
        with open('static/nmap_detections.txt', 'w') as f:
            f.write("No data available for scan detection")
        return

    scan_results = []
    
    for src_ip in df['src_ip'].unique():
        try:
            src_data = df[df['src_ip'] == src_ip]
            
            if len(src_data) < 2:
                continue
                
            time_diff = (src_data['timestamp'].max() - src_data['timestamp'].min()).total_seconds()
            if time_diff == 0:
                packet_rate = len(src_data)
            else:
                packet_rate = len(src_data) / time_diff
            
            unique_ports = len(src_data['dst_port'].unique())
            small_packets = len(src_data[src_data['length'] < 100])
            
            if (unique_ports > 10 and packet_rate > 2) or (len(src_data) > 0 and small_packets / len(src_data) > 0.8):
                scan_results.append(f"""
Potential scan detected from {src_ip}:
- Unique ports scanned: {unique_ports}
- Packet rate: {packet_rate:.2f} packets/second
- Small packet ratio: {small_packets/len(src_data):.2%}
""")
        except Exception as e:
            print(f"Error analyzing IP {src_ip}: {str(e)}")
            continue
    
    with open('static/nmap_detections.txt', 'w') as f:
        if scan_results:
            f.write('\n'.join(scan_results))
        else:
            f.write("No suspicious scanning activity detected.")

def detect_ddos_attacks(df, packet_threshold=1000, time_window=60):
    """Phát hiện các dấu hiệu tấn công DDoS"""
    if df.empty:
        with open('static/ddos_detections.txt', 'w') as f:
            f.write("No data available for DDoS detection")
        return

    ddos_results = []
    
    try:
        if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        for src_ip in df['src_ip'].unique():
            src_data = df[df['src_ip'] == src_ip].copy()
            
            # Tính số lượng gói tin trong các khoảng thời gian
            src_data['time_window'] = src_data['timestamp'].dt.floor('1min')
            packets_per_window = src_data.groupby('time_window').size()
            
            # Kiểm tra các dấu hiệu DDoS
            max_packets = packets_per_window.max()
            avg_packet_size = src_data['length'].mean()
            unique_destinations = src_data['dst_ip'].nunique()
            
            if max_packets > packet_threshold:
                ddos_results.append(f"""
Potential DDoS attack detected from {src_ip}:
- Maximum packets per minute: {max_packets}
- Average packet size: {avg_packet_size:.2f} bytes
- Number of target IPs: {unique_destinations}
- Time window with most traffic: {packets_per_window.idxmax()}
- Attack type: {'Volume-based DDoS' if avg_packet_size > 100 else 'Protocol-based DDoS'}
{'='*50}
""")
                
                # Tạo biểu đồ phân tích
                plt.figure(figsize=(10, 5))
                packets_per_window.plot(kind='bar')
                plt.title(f'Traffic pattern from {src_ip}')
                plt.xlabel('Time')
                plt.ylabel('Packets per minute')
                plt.xticks(rotation=45)
                plt.tight_layout()
                plt.savefig(f'static/ddos_analysis_{src_ip.replace(".", "_")}.png')
                plt.close()
                
    except Exception as e:
        print(f"Error in DDoS detection: {str(e)}")
    
    with open('static/ddos_detections.txt', 'w') as f:
        if ddos_results:
            f.write('\n'.join(ddos_results))
        else:
            f.write("No DDoS attacks detected.")

if __name__ == '__main__':
    analyze_traffic()

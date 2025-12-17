from scapy.all import sniff, IP
import sqlite3
import time
from database import insert_traffic_data

def packet_callback(packet):
    """Callback function để xử lý gói tin"""
    if IP in packet:
        try:
            # Trích xuất thông tin từ gói tin
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            length = len(packet)
            
            # Xác định protocol
            if protocol == 6:  # TCP
                protocol = 'TCP'
                src_port = packet.sport if hasattr(packet, 'sport') else None
                dst_port = packet.dport if hasattr(packet, 'dport') else None
            elif protocol == 17:  # UDP
                protocol = 'UDP'
                src_port = packet.sport if hasattr(packet, 'sport') else None
                dst_port = packet.dport if hasattr(packet, 'dport') else None
            else:
                protocol = 'OTHER'
                src_port = None
                dst_port = None
            
            # Lưu vào database
            insert_traffic_data(src_ip, dst_ip, protocol, length, src_port, dst_port)
            
        except Exception as e:
            print(f"Error processing packet: {str(e)}")

def start_monitoring():
    """Bắt đầu giám sát mạng"""
    try:
        print("Starting network monitoring...")
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\nStopping network monitoring...")
    except Exception as e:
        print(f"Error in network monitoring: {str(e)}")

if __name__ == '__main__':
    start_monitoring()

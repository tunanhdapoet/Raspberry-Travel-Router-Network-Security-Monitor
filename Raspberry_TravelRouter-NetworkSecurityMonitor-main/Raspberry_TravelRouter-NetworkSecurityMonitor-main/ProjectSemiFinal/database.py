import sqlite3
from datetime import datetime
import os

def init_db():
    """Khởi tạo database"""
    try:
        conn = sqlite3.connect('network_data.db')
        cursor = conn.cursor()
        
        # Tạo bảng network_traffic nếu chưa tồn tại
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS network_traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            length INTEGER,
            src_port INTEGER,
            dst_port INTEGER
        )
        ''')
        
        # Tạo index cho các trường thường được truy vấn
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON network_traffic(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_src_ip ON network_traffic(src_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_dst_ip ON network_traffic(dst_ip)')
        
        conn.commit()
        conn.close()
        print("Database initialized successfully")
    except Exception as e:
        print(f"Error initializing database: {str(e)}")

def insert_traffic_data(src_ip, dst_ip, protocol, length, src_port=None, dst_port=None):
    """Thêm dữ liệu traffic vào database"""
    try:
        conn = sqlite3.connect('network_data.db')
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO network_traffic (timestamp, src_ip, dst_ip, protocol, length, src_port, dst_port)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (datetime.now(), src_ip, dst_ip, protocol, length, src_port, dst_port))
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error inserting traffic data: {str(e)}")

def get_recent_traffic(limit=100):
    """Lấy dữ liệu traffic gần đây nhất"""
    try:
        conn = sqlite3.connect('network_data.db')
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT timestamp, src_ip, dst_ip, protocol, length
        FROM network_traffic
        ORDER BY timestamp DESC
        LIMIT ?
        ''', (limit,))
        
        data = cursor.fetchall()
        conn.close()
        
        return data
    except Exception as e:
        print(f"Error getting recent traffic: {str(e)}")
        return []

def clear_old_data(days=7):
    """Xóa dữ liệu cũ hơn số ngày chỉ định"""
    try:
        conn = sqlite3.connect('network_data.db')
        cursor = conn.cursor()
        
        cursor.execute('''
        DELETE FROM network_traffic
        WHERE timestamp < datetime('now', '-? days')
        ''', (days,))
        
        conn.commit()
        conn.close()
        print(f"Cleared data older than {days} days")
    except Exception as e:
        print(f"Error clearing old data: {str(e)}")

if __name__ == '__main__':
    init_db()

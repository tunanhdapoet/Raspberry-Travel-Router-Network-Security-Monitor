import threading
import time
from datetime import datetime, timedelta
import sqlite3
import subprocess


class IPBlocker:
    def __init__(self):
        self.blocked_ips = {}  # {ip: unblock_time}
        self.lock = threading.Lock()

        # Khởi tạo database cho blocked IPs
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect('network_data.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips
                    (ip TEXT PRIMARY KEY,
                     block_time DATETIME,
                     unblock_time DATETIME,
                     reason TEXT,
                     manual_block BOOLEAN)''')
        conn.commit()
        conn.close()

    def block_ip(self, ip, duration_minutes=2, reason="", manual=False):
        with self.lock:
            current_time = datetime.now()
            unblock_time = current_time + timedelta(minutes=duration_minutes)

            # Thêm rule vào iptables
            try:
                subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error adding iptables rule: {e}")
                return False

            conn = sqlite3.connect('network_data.db')
            c = conn.cursor()
            c.execute('''INSERT OR REPLACE INTO blocked_ips 
                        (ip, block_time, unblock_time, reason, manual_block)
                        VALUES (?, ?, ?, ?, ?)''',
                      (ip, current_time, unblock_time, reason, manual))
            conn.commit()
            conn.close()

            self.blocked_ips[ip] = unblock_time

            # Tạo thread để tự động unblock
            if not manual:
                threading.Timer(duration_minutes * 60, self.unblock_ip, args=[ip]).start()

            return True

    def unblock_ip(self, ip):
        with self.lock:
            if ip in self.blocked_ips:
                # Xóa rule từ iptables
                try:
                    subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                except subprocess.CalledProcessError as e:
                    print(f"Error removing iptables rule: {e}")
                    return False

                conn = sqlite3.connect('network_data.db')
                c = conn.cursor()
                c.execute('DELETE FROM blocked_ips WHERE ip = ?', (ip,))
                conn.commit()
                conn.close()

                del self.blocked_ips[ip]
                return True
            return False

    def is_blocked(self, ip):
        with self.lock:
            if ip in self.blocked_ips:
                if datetime.now() > self.blocked_ips[ip]:
                    self.unblock_ip(ip)
                    return False
                return True
            return False

    def get_blocked_ips(self):
        conn = sqlite3.connect('network_data.db')
        c = conn.cursor()
        c.execute('''SELECT ip, block_time, unblock_time, reason, manual_block 
                    FROM blocked_ips''')
        blocked = c.fetchall()
        conn.close()

        return [{'ip': row[0],
                 'block_time': row[1],
                 'unblock_time': row[2],
                 'reason': row[3],
                 'manual_block': row[4]} for row in blocked]


# Tạo instance global
ip_blocker = IPBlocker()

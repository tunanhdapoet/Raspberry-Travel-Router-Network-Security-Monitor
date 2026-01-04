# Network Security Monitor & Access Point trên Raspberry Pi 4 🛡️🍓

![Raspberry Pi](https://img.shields.io/badge/Hardware-Raspberry_Pi_4-C51A4A?logo=raspberry-pi)
![Python](https://img.shields.io/badge/Backend-Python_Flask-blue?logo=python)
![RaspAP](https://img.shields.io/badge/Network-RaspAP-green)
![Scapy](https://img.shields.io/badge/Security-Scapy-red)

Đồ án môn học **Hệ thống nhúng mạng không dây (NT131.P13)**.

Dự án biến Raspberry Pi 4 thành một **Wireless Access Point (Điểm truy cập không dây)** mạnh mẽ, tích hợp ứng dụng **Network Security Monitor** để giám sát lưu lượng mạng, bắt gói tin và phát hiện các hành vi tấn công mạng cơ bản trong thời gian thực.

---

## 📖 Mục lục
- [Giới thiệu](#-giới-thiệu)
- [Tính năng chính](#-tính-năng-chính)
- [Kiến trúc hệ thống](#-kiến-trúc-hệ-thống)
- [Yêu cầu phần cứng](#-yêu-cầu-phần-cứng)
- [Cài đặt & Triển khai](#-cài-đặt--triển-khai)
- [Thành viên thực hiện](#-thành-viên-thực-hiện)

---

## 🚀 Giới thiệu

Với sự phát triển của IoT, nhu cầu về một thiết bị giám sát mạng nhỏ gọn, chi phí thấp là rất lớn. Dự án này kết hợp **RaspAP** (để quản lý kết nối Wi-Fi) và một ứng dụng **Python Flask** tự phát triển để thực hiện các chức năng bảo mật.

**Mục tiêu:**
1.  Cung cấp kết nối Wi-Fi ổn định cho các thiết bị IoT/Mobile.
2.  Giám sát tài nguyên hệ thống (CPU, RAM) và lưu lượng mạng (Upload/Download).
3.  Phát hiện sớm các dấu hiệu tấn công mạng như Port Scanning hoặc DDoS.

---

## ✨ Tính năng chính

### 1. Quản lý mạng không dây (Wireless Access Point)
* Sử dụng **RaspAP** để biến Raspberry Pi thành Router.
* Hỗ trợ cấu hình SSID, mật khẩu, DHCP Server, và Bridged Mode (kết nối LAN ra Internet).
* Giao diện quản lý Wi-Fi trực quan.

### 2. Giám sát hệ thống & Lưu lượng (System Monitor)
* Hiển thị thông số **CPU Usage**, **RAM Usage** theo thời gian thực.
* Biểu đồ lưu lượng mạng (Network Traffic) trực quan sử dụng **Chart.js**, cập nhật liên tục tốc độ gửi/nhận gói tin.

### 3. Phân tích & Bắt gói tin (Packet Sniffer)
* Cho phép người dùng **Bắt đầu (Start)** và **Dừng (Stop)** quá trình bắt gói tin trên giao diện Web.
* Lưu trữ gói tin dưới dạng file `.pcap` để phục vụ phân tích chuyên sâu (Forensics).
* Thống kê phân bố giao thức (TCP, UDP, ICMP...) và Top địa chỉ IP nguồn/đích.

### 4. Hệ thống phát hiện xâm nhập cơ bản (Mini IDS)
Sử dụng thư viện **Scapy** để phân tích luồng dữ liệu và cảnh báo các hành vi bất thường:
* 🚨 **Phát hiện SYN Scan:** Nhận diện hành vi quét cổng TCP.
* 🚨 **Phát hiện UDP Scan:** Nhận diện hành vi dò tìm dịch vụ UDP.
* 🚨 **Cảnh báo High Traffic:** Phát hiện lưu lượng tăng đột biến (dấu hiệu của DoS/DDoS).

---

## 🏗 Kiến trúc hệ thống

* **Phần cứng:** Raspberry Pi 4 đóng vai trò trung tâm xử lý.
* **Hệ điều hành:** Raspberry Pi OS Lite (64-bit) tối ưu hiệu năng.
* **Backend:** Python Flask Server + Scapy (Network manipulation) + Psutil (System monitoring).
* **Frontend:** HTML5, CSS3, JavaScript (AJAX cập nhật dữ liệu không cần reload trang).
* **Network Stack:** `hostapd` (Access Point), `dnsmasq` (DNS/DHCP), `dhcpcd`.

---

## 🛠 Yêu cầu phần cứng

* **Board:** Raspberry Pi 4 Model B (Khuyên dùng bản 4GB/8GB RAM).
* **Thẻ nhớ:** MicroSD tối thiểu 32GB (Class 10).
* **Nguồn:** USB-C 5V/3A chuẩn.
* **Mạng:** Cáp Ethernet (kết nối Internet).

---

## ⚙️ Cài đặt & Triển khai

### Bước 1: Cài đặt Hệ điều hành & RaspAP
1.  Flash **Raspberry Pi OS Lite (64-bit)** vào thẻ nhớ.
2.  Kết nối SSH vào Raspberry Pi.
3.  Cài đặt **RaspAP** bằng lệnh Quick Installer:
    ```bash
    curl -sL [https://install.raspap.com](https://install.raspap.com) | bash
    ```
4.  Làm theo hướng dẫn trên màn hình để thiết lập AP (Interface: `wlan0`).

### Bước 2: Cài đặt ứng dụng Network Monitor
1.  Cài đặt các thư viện Python cần thiết:
    ```bash
    sudo apt-get update
    sudo apt-get install python3-pip
    pip3 install flask scapy psutil netifaces
    ```
2.  Clone mã nguồn dự án về thư mục `/home/pi/`:
    ```bash
    git clone [https://github.com/username/network-security-monitor.git](https://github.com/username/network-security-monitor.git)
    cd network-security-monitor
    ```

### Bước 3: Chạy ứng dụng
Vì ứng dụng cần quyền truy cập card mạng (promiscuous mode), cần chạy với quyền `sudo`:
```bash
sudo python3 app.py
# NT204.R11.ANTN - Hệ thống phát hiện xâm nhập (IDS)

**Sinh viên:** Nguyễn Tuấn Hùng - 24520616

## Mô tả

IDS đơn giản viết bằng Python, sử dụng Scapy để bắt và phân tích gói tin mạng theo thời gian thực.

## Chức năng

- Bắt gói tin mạng (packet capture)
- Phân tích giao thức: TCP, UDP, DNS, HTTP
- Phát hiện tấn công:
  - **Port Scan** - quét cổng
  - **Brute Force** - dò mật khẩu SSH/FTP/RDP
  - **SYN Flood** - tấn công DDoS
  - **DNS Anomaly** - DNS tunneling, DNS flood

## Cài đặt

```bash
pip install -r requirements.txt
```

## Chạy

```bash
# Chạy mặc định
sudo python3 main.py

# Chọn interface
sudo python3 main.py eth0

# Có bộ lọc
sudo python3 main.py eth0 "tcp port 80"
```

## Cấu trúc

```
├── main.py          # Entry point
├── capture.py       # Bắt gói tin
├── parsers.py       # Phân tích TCP/UDP/DNS/HTTP
├── detectors.py     # Phát hiện tấn công
├── alert.py         # Hệ thống cảnh báo
├── TEST/            # Kết quả test
└── logs/            # File log cảnh báo
```

## Sử dụng AI

- **Công cụ:** Claude (Anthropic)
- **Mục đích:** Tham khảo kiến thức, giải thích khái niệm, đưa ra lời khuyên về cách tiếp cận, gợi ý cấu trúc code

# NT204.R11.ANTN - Hệ thống phát hiện xâm nhập (IDS)

**Sinh viên:** Nguyễn Tuấn Hùng - 24520616

## Mô tả

IDS đơn giản viết bằng Python, sử dụng Scapy để bắt và phân tích gói tin mạng theo thời gian thực.

## Pipeline

```
Packet Capture & Parser -> Decoder -> Preprocessor -> Flow/Connection Tracker -> Detection
```

## Chức năng

### Bài tập 1
- Bắt gói tin mạng (packet capture)
- Phân tích giao thức: TCP, UDP, DNS, HTTP
- Phát hiện tấn công:
  - **Port Scan** - quét cổng
  - **Brute Force** - dò mật khẩu SSH/FTP/RDP
  - **SYN Flood** - tấn công DDoS
  - **DNS Anomaly** - DNS tunneling, DNS flood

### Bài tập 2
- **Decoder** - giải mã URL/percent, HTML entity, Base64/Quoted-Printable, ASCII/UTF-8
- **Preprocessor** - validation (valid/partial/invalid), chuẩn hóa, xử lý field thiếu, gắn metadata
- **Flow/Connection Tracker** - gom packet thành flow 2 chiều (5-tuple), theo dõi trạng thái TCP
  (NEW/HANDSHAKE/ESTABLISHED/CLOSING/CLOSED/RESET), timeout UDP/TCP, thống kê packet/byte/flag

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
├── main.py          # Entry point (chạy cả pipeline)
├── capture.py       # Bắt gói tin
├── parsers.py       # Phân tích TCP/UDP/DNS/HTTP
├── detectors.py     # Phát hiện tấn công
├── alert.py         # Hệ thống cảnh báo
├── decoder.py       # Giải mã URL/HTML/MIME/charset
├── preprocessor.py  # Validation + chuẩn hóa
├── flow_tracker.py  # Flow/Connection tracker
├── TEST/            # Test cases T01-T14
└── logs/            # File log cảnh báo
```

## Test

```bash
cd TEST
python3 test_decoder.py        # T01-T04
python3 test_preprocessor.py   # T05, T06, T14
python3 test_flow_tracker.py   # T07-T13
```

## Sử dụng AI

- **Công cụ:** Claude (Anthropic)
- **Mục đích:** Tham khảo kiến thức, giải thích khái niệm, đưa ra lời khuyên về cách tiếp cận, gợi ý cấu trúc code

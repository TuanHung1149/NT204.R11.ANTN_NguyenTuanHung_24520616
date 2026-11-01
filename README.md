# NT204.R11.ANTN - Hệ thống phát hiện xâm nhập (IDS)

**Sinh viên:** Nguyễn Tuấn Hùng - 24520616

## Mô tả

IDS đơn giản viết bằng Python, sử dụng Scapy để bắt và phân tích gói tin mạng theo thời gian thực.

## Pipeline

```
Packet Capture & Parser -> Decoder -> Preprocessor -> Flow/Connection Tracker
    -> Evaluation Engine -> Repository/Indexer -> Matching Engine -> Detection Event
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

### Bài tập 3 - Core Engine & Snort rule matching
- **Rule Loader** - đọc file `.rules`, bỏ comment/dòng trống, thay biến `$HOME_NET`, bật/tắt rule qua config
- **Rule Parser & Validator** - tách header/options thành Internal Rule Object, phân loại valid/invalid/unsupported kèm lý do
- **Rule Repository / Indexer** - đánh chỉ mục theo protocol/port để chọn candidate, không duyệt toàn bộ rule
- **Rule Matching Engine** - so khớp header (any/CIDR/port range/`->`/`<>`), flow (to_server/to_client,
  established/not_established), `flags`, `dsize`, `content` (nocase, offset, depth, distance, within)
- **Rule Evaluation Engine** - lấy candidate, chạy matcher, cho phép nhiều rule cùng match, thống kê hiệu năng
- **Detection Event Generator** - sinh Detection Event đủ sid/rev/msg/priority/5-tuple/flow_id/match info

**Phạm vi Snort hỗ trợ:** `alert`; `tcp/udp/ip`; IP `any`/IPv4/CIDR/list/`!`; port `any`/đơn/range/list;
`-> <>`; `msg sid rev`; `content nocase offset depth distance within`; `flags dsize`; `flow`; `classtype priority`.
Keyword ngoài phạm vi (`pcre`, `byte_test`, `flowbits`...) được đánh dấu **unsupported**, không làm dừng chương trình.

**Quy ước:** `dsize:A<>B` tính **inclusive** hai đầu. `content` tìm trong payload thô; nếu payload rỗng
thì tìm trong application data đã parse/decode (DNS qname, URI đã giải mã).

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
├── rule_loader.py       # Nạp file rule + config
├── rule_parser.py       # Parse/validate rule -> Internal Rule Object
├── rule_repository.py   # Lưu rule + đánh chỉ mục candidate
├── rule_matcher.py      # So khớp rule với event
├── evaluation_engine.py # Điều phối đánh giá event
├── detection_event.py   # Sinh Detection Event
├── rules/           # File .rules (không hard-code trong source)
├── config/          # engine.json: biến, bật/tắt rule
├── TEST/            # Test bài 1-2
├── TEST/BT3/        # Test bài 3 (T01-T14) + kết quả
└── logs/            # File log cảnh báo
```

## Test

```bash
# Bài 1-2
cd TEST
python3 test_decoder.py        # T01-T04
python3 test_preprocessor.py   # T05, T06, T14
python3 test_flow_tracker.py   # T07-T13

# Bài 3 - chạy cả 14 test case
cd TEST/BT3
python3 run_all.py
```

## Demo

```bash
python3 main.py --pcap TEST/BT3/demo_bt3.pcap
```

## Sử dụng AI

- **Công cụ:** Claude (Anthropic), qua Claude Code.
- **Mục đích:** Hỏi kiến thức nền (cấu trúc IDS, cú pháp Snort rule, cách dùng Scapy), nhờ sinh mã
  nguồn theo yêu cầu, rà soát lỗi và đề xuất test case.
- **Cách làm việc:** Sinh viên mô tả yêu cầu theo đề bài → Claude sinh mã nguồn → sinh viên đọc hiểu,
  chạy kiểm thử, yêu cầu sửa khi sai hoặc khi muốn đổi cách làm (ví dụ: yêu cầu bỏ bớt comment/docstring,
  yêu cầu giữ code đơn giản, yêu cầu sửa lại cách lấy payload và cách đánh chỉ mục rule).

**Phần mã nguồn có sử dụng AI:**

| Bài | File | Mức độ |
|-----|------|--------|
| 1 | `capture.py`, `parsers.py`, `detectors.py`, `alert.py`, `main.py` | Claude sinh mã nguồn theo yêu cầu; sinh viên đọc hiểu, chạy thử và yêu cầu chỉnh sửa |
| 2 | `decoder.py`, `preprocessor.py`, `flow_tracker.py` | Như trên |
| 3 | `rule_loader.py`, `rule_parser.py`, `rule_repository.py`, `rule_matcher.py`, `evaluation_engine.py`, `detection_event.py` | Như trên |
| 1-3 | `TEST/`, `TEST/BT3/` | Claude sinh script kiểm thử; sinh viên chạy và đối chiếu kết quả với đề bài |
| - | `rules/community.rules` | Không do AI sinh — bộ rule Snort Community tải từ snort.org (xem `rules/COMMUNITY-RULES-LICENSE`) |

Sinh viên chịu trách nhiệm về toàn bộ mã nguồn đã nộp và có thể giải thích cách hoạt động của từng module.

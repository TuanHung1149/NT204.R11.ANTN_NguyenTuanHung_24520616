from common import event, check, finish
from scapy.all import IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, ICMP
import decoder
import parsers
from preprocessor import preprocess, validate
from rule_parser import parse_rule
from rule_matcher import match_rule, match_flow, _find
from pipeline import IDSPipeline

print("T18 - Cac nhanh xu ly loi va truong hop bien (yeu cau 'khong crash')")

# ---------- Decoder ----------
print("\n  [Decoder]")
val, st = decoder.decode_form_urlencoded("a+b%3Dc")
check((val, st) == ("a b=c", "ok"), "form-urlencoded: '+' thanh khoang trang")

val, st = decoder.decode_base64("!!!khong-phai-base64!!!")
check(st == "error", "base64 hong -> bao error, khong crash")

val, st = decoder.decode_mime("abc", "unknown-encoding")
check(st == "none", "encoding la khong biet -> tra ve nguyen ban")

val, st = decoder.decode_bytes("da la chuoi roi")
check(st == "ok", "decode_bytes nhan san chuoi")

val, st = decoder.decode_quoted_printable(b"a=3Db")
check((val, st) == ("a=b", "ok"), "quoted-printable nhan bytes")

ev = decoder.decode_event({
    "type": "HTTP", "path": "/a%20b",
    "headers": {"content-transfer-encoding": "base64"}, "body": "SGk=",
})
check(ev["decoded_path"] == "/a b", "giai ma duong dan HTTP")
check(ev["decoded_body"] == "Hi", "giai ma body MIME theo header")
check(ev["decode_status"]["body"] == "ok", "co ghi trang thai giai ma")

# ---------- Parsers ----------
print("\n  [Parsers]")
check(parsers.parse_tcp(IP()/UDP()) is None, "parse_tcp voi goi UDP -> None")
check(parsers.parse_udp(IP()/TCP()) is None, "parse_udp voi goi TCP -> None")
check(parsers.parse_dns(IP()/TCP()) is None, "parse_dns voi goi khong co DNS -> None")
check(parsers.parse_http(IP()/TCP(dport=22)/Raw(load=b"SSH-2.0")) is None,
      "parse_http voi port khong phai HTTP -> None")
check(parsers.parse_http(IP()/TCP(dport=80)/Raw(load=b"\xff\xfe rac")) is None,
      "payload khong phai HTTP -> None, khong crash")
check(parsers.parse_packet(IP()/ICMP()) is None, "goi ICMP -> None")

dns_resp = parsers.parse_dns(IP()/UDP()/DNS(qr=1, qd=DNSQR(qname="a.com"),
                                            an=DNSRR(rrname="a.com", rdata="1.2.3.4")))
check(dns_resp["is_query"] is False, "nhan dien DNS response")
check(dns_resp["answers"][0]["data"] == "1.2.3.4", "doc duoc phan tra loi DNS")

# ---------- Preprocessor ----------
print("\n  [Preprocessor]")
check(validate({"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "protocol": "tcp",
                "src_port": 99999})[0] == "partial", "src_port ngoai pham vi -> partial")
check(validate({"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "protocol": "tcp",
                "dst_port": -5})[0] == "partial", "dst_port am -> partial")
check(validate({"src_ip": "khong-phai-ip", "dst_ip": "10.0.0.2",
                "protocol": "tcp"})[0] == "partial", "src_ip sai dinh dang -> partial")
check(validate({"src_ip": "10.0.0.1", "dst_ip": "999.1.1.1",
                "protocol": "tcp"})[0] == "partial", "dst_ip sai dinh dang -> partial")
check(validate({"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                "protocol": "sctp"})[0] == "partial", "protocol la khong biet -> partial")
check(preprocess(None)["processing_action"] == "drop", "input None -> drop, khong crash")
check(preprocess([1, 2, 3])["preprocess_status"] == "invalid", "input sai kieu -> invalid")
check(preprocess({"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "protocol": "udp",
                  "headers": None})["headers"] == {}, "headers None -> dict rong")

# ---------- Matcher ----------
print("\n  [Matcher]")
r = parse_rule('alert tcp 10.0.0.0/8 any -> any any (msg:"x"; sid:1;)')
check(not match_rule(r, event(src_ip="khong-phai-ip"))["match"],
      "IP trong event sai dinh dang -> khong match, khong crash")

r_any = parse_rule('alert ip any any -> any any (msg:"x"; sid:2;)')
check(match_rule(r_any, event(protocol="udp", src_port=None, dst_port=None))["match"],
      "event khong co port van khop rule 'any'")

r_port = parse_rule('alert tcp any any -> any 80 (msg:"x"; sid:3;)')
check(not match_rule(r_port, event(dst_port=None))["match"],
      "event khong co port -> khong khop rule yeu cau port 80")

r_neg = parse_rule('alert tcp !10.0.0.0/8 any -> any any (msg:"x"; sid:4;)')
check(not match_rule(r_neg, event(src_ip="10.0.0.5"))["match"], "phu dinh IP: loai dung")
check(match_rule(r_neg, event(src_ip="192.168.1.5"))["match"], "phu dinh IP: cho qua dung")

r_flow = parse_rule('alert tcp any any -> any 80 (msg:"x"; flow:to_client; sid:5;)')
check(not match_rule(r_flow, event(), {"to_server": True})["match"], "to_client voi goi to_server -> loai")

r_ne = parse_rule('alert tcp any any -> any 80 (msg:"x"; flow:not_established; sid:6;)')
check(not match_rule(r_ne, event(), {"established": True})["match"], "not_established voi flow da mo -> loai")
check(match_flow({"flow": {"state": "established"}}, None)[0] is False,
      "rule can flow nhung khong co context -> loai")
check(_find(b"abc", b"a", False, 5, 2) == -1, "cua so tim rong -> tra -1")

# ---------- Rule parser: cac loi cu phap ----------
print("\n  [Rule parser]")
bad = [
    ('alert tcp any any -> any 80 (msg:"x"; content:"|ZZ|"; sid:1;)', "byte hex khong hop le"),
    ('alert tcp any any -> any 80 (msg:"x"; content:"|2E 2E"; sid:2;)', "khoi hex thieu dau"),
    ('alert tcp any any -> any 80 (msg:"x"; content; sid:3;)', "content thieu gia tri"),
    ('alert tcp any any -> any 80 (msg:"x"; flags:; sid:4;)', "flags thieu gia tri"),
    ('alert tcp any any -> any 80 (msg:"x"; flags:XYZ; sid:5;)', "flags ky tu la"),
    ('alert tcp any any -> any 80 (msg:"x"; dsize:; sid:6;)', "dsize thieu gia tri"),
    ('alert tcp any any -> any 80 (msg:"x"; depth:abc; content:"a"; sid:7;)', "depth khong phai so"),
    ('alert tcp any any -> any 80 msg:"x"; sid:8;', "thieu dau ngoac"),
    ('alert tcp 10.0.0.300 any -> any 80 (msg:"x"; sid:9;)', "IP ngoai pham vi"),
    ('alert tcp any 100:50 -> any 80 (msg:"x"; sid:10;)', "port range nguoc"),
    ('alert tcp any [] -> any 80 (msg:"x"; sid:11;)', "danh sach port rong"),
]
for text, label in bad:
    r = parse_rule(text)
    check(r["status"] in ("invalid", "unsupported"), f"{label} -> {r['status']}")

r = parse_rule('alert tcp any any -> any 80 (msg:"x"; dsize:abc; sid:12;)')
check(not match_rule(r, event())["match"], "dsize sai dinh dang -> khong match, khong crash")

# ---------- Pipeline: goi khong co IP ----------
print("\n  [Pipeline]")
pipe = IDSPipeline()
check(pipe.process(IP()/ICMP()) == [], "goi ICMP khong sinh detection")
check(pipe.build_event(DNS()) is None, "goi khong co lop IP -> None")

finish("T18")

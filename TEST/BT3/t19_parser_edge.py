from common import check, finish
from scapy.all import IP, TCP, Raw
from parsers import parse_http
from rule_parser import parse_rule, split_options, parse_content_pattern

print("T19 - Cac truong hop bien khi phan tich rule")

print("\n  [Header]")
cases = [
    ('alert tcp [1.1.1.1,!2.2.2.2] any -> any 80 (msg:"x"; sid:1;)',
     "unsupported", "phu dinh ben trong danh sach IP"),
    ('alert tcp any [80,!81] -> any 80 (msg:"x"; sid:2;)',
     "unsupported", "phu dinh ben trong danh sach port"),
    ('alert tcp $CHUA_DINH_NGHIA any -> any 80 (msg:"x"; sid:3;)',
     "invalid", "bien IP chua dinh nghia"),
    ('alert tcp any $PORT_LA -> any 80 (msg:"x"; sid:4;)',
     "invalid", "bien port chua dinh nghia"),
    ('alert tcp any any <- any 80 (msg:"x"; sid:5;)',
     "invalid", "huong '<-' khong hop le"),
    ('alert tcp [,] any -> any 80 (msg:"x"; sid:6;)',
     "invalid", "danh sach IP rong"),
    ('alert tcp any [,] -> any 80 (msg:"x"; sid:7;)',
     "invalid", "danh sach port rong"),
    ('alert tcp any a:b -> any 80 (msg:"x"; sid:8;)',
     "invalid", "port khong phai so"),
]
for text, want, label in cases:
    r = parse_rule(text)
    check(r["status"] == want, f"{label} -> {r['status']}")

# 'any' nam trong danh sach thi ca danh sach thanh 'any'
r = parse_rule('alert tcp [any,10.0.0.1] [any,80] -> any 80 (msg:"x"; sid:9;)')
check(r["status"] == "valid", "danh sach co 'any' van hop le")
check(r["header"]["src_ip"]["any"] is True, "danh sach IP co 'any' -> any")
check(r["header"]["src_port"]["any"] is True, "danh sach port co 'any' -> any")

print("\n  [Content]")
content_cases = [
    ('content:abc;', "invalid", "content khong dat trong dau nhay"),
    ('content:"abc;', "invalid", "content thieu dau nhay dong"),
    ('content:"a",nocase;', "unsupported", "tham so kieu Snort3 sau dau nhay"),
    ('content:!"a";', "unsupported", "content phu dinh"),
]
for opt, want, label in content_cases:
    r = parse_rule(f'alert tcp any any -> any 80 (msg:"x"; {opt} sid:20;)')
    check(r["status"] == want, f"{label} -> {r['status']}")

# Ky tu escape
r = parse_rule(r'alert tcp any any -> any 80 (msg:"x"; content:"say \"hi\""; sid:21;)')
check(r["status"] == "valid" and r["contents"][0]["pattern"] == b'say "hi"',
      "escape dau nhay trong content")
r = parse_rule(r'alert tcp any any -> any 80 (msg:"x"; content:"a\;b"; sid:22;)')
check(r["status"] == "valid" and r["contents"][0]["pattern"] == b"a;b",
      "escape dau cham phay trong content")
check(parse_content_pattern(r"a\\b") == b"a\\b", "escape dau gach cheo nguoc")

print("\n  [Options]")
# Option cuoi khong co dau ';' van phai doc duoc
r = parse_rule('alert tcp any any -> any 80 (msg:"x"; content:"a"; sid:23)')
check(r["status"] == "valid" and r["sid"] == 23, "option cuoi khong co dau ';'")
check(split_options('msg:"a"; sid:1') == ['msg:"a"', "sid:1"], "tach option khi thieu ';' cuoi")

# flow co phan tu rong
r = parse_rule('alert tcp any any -> any 80 (msg:"x"; flow:to_server,,established; sid:24;)')
check(r["status"] == "valid", "flow co phan tu rong van doc duoc")
check(r["flow"] == {"direction": "to_server", "state": "established"}, "doc dung ca 2 gia tri flow")

# Alias flow
r = parse_rule('alert tcp any any -> any 80 (msg:"x"; flow:from_client,established; sid:25;)')
check(r["flow"]["direction"] == "to_server", "from_client dong nghia to_server")
r = parse_rule('alert tcp any any -> any 80 (msg:"x"; flow:from_server; sid:26;)')
check(r["flow"]["direction"] == "to_client", "from_server dong nghia to_client")

print("\n  [Parsers]")
check(parse_http(IP()/TCP(dport=80)/Raw(load=b"")) is None, "payload HTTP rong -> None")

finish("T19")

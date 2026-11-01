from common import event, check, finish
from rule_parser import parse_rule
from rule_matcher import match_rule

print("T07 - Header khong khop thi loai truoc khi so khop content")

# Payload CO chua content, nhung header sai -> van phai NO_MATCH o buoc header
ev = event(src_ip="10.0.0.5", dst_ip="10.0.0.9", dst_port=80,
           payload=b"GET /admin HTTP/1.1\r\n")

cases = [
    ("sai port dich", 'alert tcp any any -> any 443 (msg:"x"; content:"admin"; sid:700001;)'),
    ("sai IP nguon", 'alert tcp 192.168.9.9 any -> any 80 (msg:"x"; content:"admin"; sid:700002;)'),
    ("sai protocol", 'alert udp any any -> any 80 (msg:"x"; content:"admin"; sid:700003;)'),
    ("sai CIDR dich", 'alert tcp any any -> 172.16.0.0/12 80 (msg:"x"; content:"admin"; sid:700004;)'),
]

for label, text in cases:
    res = match_rule(parse_rule(text), ev)
    print(f"  {label:16} -> match={res['match']} stage={res['stage']} ({res['reason']})")
    check(not res["match"], f"{label}: khong match")
    check(res["stage"] == "header", f"{label}: dung lai o buoc header")
    check(res["matched"] == [], f"{label}: khong co ket qua content")

# Doi chung: header dung thi moi chay toi content va match duoc
ok = match_rule(parse_rule('alert tcp any any -> any 80 (msg:"ok"; content:"admin"; sid:700005;)'), ev)
print(f"  header dung      -> match={ok['match']} content={ok['matched']}")
check(ok["match"], "header dung thi content moi duoc so khop")

finish("T07")

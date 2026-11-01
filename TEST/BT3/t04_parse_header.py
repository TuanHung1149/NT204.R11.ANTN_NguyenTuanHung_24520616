import ipaddress
from common import check, finish
from rule_parser import parse_rule

print("T04 - Parse header TCP voi any / IP don / CIDR / port range")

r = parse_rule('alert tcp 192.168.1.10 1024: -> 10.0.0.0/8 80 '
               '(msg:"header"; content:"a"; sid:400001; rev:2;)')
h = r["header"]
print(f"  status={r['status']} action={h['action']} proto={h['protocol']} dir={h['direction']}")
print(f"  src_ip={h['src_ip']} src_port={h['src_port']}")
print(f"  dst_ip={h['dst_ip']} dst_port={h['dst_port']}")

check(r["status"] == "valid", "rule valid")
check(h["action"] == "alert" and h["protocol"] == "tcp", "action/protocol dung")
check(h["direction"] == "->", "direction dung")
check(r["sid"] == 400001 and r["rev"] == 2, "sid/rev dung")

# IP don le
check(h["src_ip"]["nets"] == [ipaddress.ip_network("192.168.1.10/32")], "IP don -> /32")
# CIDR
check(h["dst_ip"]["nets"] == [ipaddress.ip_network("10.0.0.0/8")], "CIDR giu nguyen prefix")
# Port range mo va port don
check(h["src_port"]["ranges"] == [(1024, 65535)], "port '1024:' -> (1024,65535)")
check(h["dst_port"]["ranges"] == [(80, 80)], "port don -> (80,80)")

# any
r2 = parse_rule('alert udp any any -> any any (msg:"any"; sid:400002;)')
h2 = r2["header"]
print(f"  any: src_ip={h2['src_ip']} dst_port={h2['dst_port']}")
check(h2["src_ip"]["any"] and h2["dst_port"]["any"], "any duoc danh dau dung")

# Danh sach port va port range dong
r3 = parse_rule('alert tcp any [80,8080] -> any :1023 (msg:"list"; sid:400003;)')
h3 = r3["header"]
print(f"  list: src_port={h3['src_port']['ranges']} dst_port={h3['dst_port']['ranges']}")
check(h3["src_port"]["ranges"] == [(80, 80), (8080, 8080)], "danh sach port dung")
check(h3["dst_port"]["ranges"] == [(0, 1023)], "port ':1023' -> (0,1023)")

finish("T04")

from common import event, check, finish
from rule_parser import parse_rule
from rule_matcher import match_rule

print("T11 - distance/within so khop tuong doi giua hai content")


def run(payload, opts, sid):
    ev = event(payload=payload)
    rule = parse_rule(f'alert tcp any any -> any 80 (msg:"t"; {opts} sid:{sid};)')
    return match_rule(rule, ev)


p1 = b"cmd.exe /c dir"
print(f"\n  [1] payload: {p1.decode()}")
r = run(p1, 'content:"cmd.exe"; content:"/c"; distance:0; within:5;', 1101)
print(f"      cmd.exe + /c distance:0 within:5 -> {'MATCH' if r['match'] else 'NO'}")
check(r["match"], "'/c' nam ngay sau cmd.exe -> match")

r = run(p1, 'content:"cmd.exe"; content:"dir"; distance:0; within:3;', 1102)
print(f"      cmd.exe + dir distance:0 within:3 -> {'MATCH' if r['match'] else 'NO'}")
check(not r["match"], "'dir' cach qua xa, ngoai within:3 -> khong match")

r = run(p1, 'content:"cmd.exe"; content:"dir"; distance:4; within:3;', 1103)
print(f"      cmd.exe + dir distance:4 within:3 -> {'MATCH' if r['match'] else 'NO'}")
check(r["match"], "distance:4 bo qua ' /c ' -> match duoc dir")

# Thu tu bat buoc: content sau phai nam SAU content truoc
p2 = b"/c cmd.exe"
print(f"\n  [2] payload: {p2.decode()}  (thu tu dao nguoc)")
r = run(p2, 'content:"cmd.exe"; content:"/c"; distance:0; within:10;', 1104)
print(f"      cmd.exe roi moi /c -> {'MATCH' if r['match'] else 'NO'}")
check(not r["match"], "'/c' nam truoc cmd.exe -> khong thoa relative matching")

# Quay lui: 'cmd.exe' xuat hien 2 lan, chi lan 2 moi co '/c' trong within
p3 = b"cmd.exe ........................ cmd.exe /c dir"
print(f"\n  [3] payload: {p3.decode()}")
print(f"      'cmd.exe' o vi tri 0 va 33")
r = run(p3, 'content:"cmd.exe"; content:"/c"; distance:0; within:5;', 1105)
offs = [(m["content"], m["offset"]) for m in r["matched"]]
print(f"      -> {'MATCH' if r['match'] else 'NO'} {offs}")
check(r["match"], "quay lui sang 'cmd.exe' thu 2 de tim duoc '/c'")
check(offs == [("cmd.exe", 33), ("/c", 41)], "chon dung cap vi tri thoa dieu kien")

# Chi co within, khong co distance
r = run(p1, 'content:"cmd.exe"; content:"/c"; within:5;', 1106)
print(f"\n      chi within:5 (khong distance) -> {'MATCH' if r['match'] else 'NO'}")
check(r["match"], "within khong kem distance van hoat dong")

finish("T11")

from common import event, check, finish
from rule_parser import parse_rule
from rule_matcher import match_rule

print("T10 - offset/depth gioi han vung tim content")

#              0123456789...
payload = b"GET /index.html?admin=1 HTTP/1.1"
ev = event(payload=payload)
print(f"  payload: {payload.decode()}")
print(f"  vi tri 'GET'=0, 'admin'=16")


def run(opts, sid):
    rule = parse_rule(f'alert tcp any any -> any 80 (msg:"t"; {opts} sid:{sid};)')
    return match_rule(rule, ev)


cases = [
    ('content:"GET"; offset:0; depth:3;', True, "GET nam tron trong [0,3)"),
    ('content:"GET"; offset:0; depth:2;', False, "depth:2 cat mat chu T -> khong match"),
    ('content:"GET"; offset:1;', False, "offset:1 bo qua vi tri 0 -> khong match"),
    ('content:"admin"; offset:0; depth:10;', False, "admin o vi tri 16, ngoai depth:10"),
    ('content:"admin"; offset:10; depth:12;', True, "admin nam trong [10,22)"),
    ('content:"admin"; offset:16;', True, "offset dung ngay vi tri admin"),
    ('content:"admin"; offset:17;', False, "offset:17 da vuot qua admin"),
    ('content:"HTTP"; depth:10;', False, "HTTP o cuoi, ngoai depth:10"),
    ('content:"HTTP";', True, "khong gioi han -> tim het payload"),
]

for i, (opts, expected, label) in enumerate(cases, start=1):
    res = run(opts, 1000 + i)
    got = res["match"]
    off = res["matched"][0]["offset"] if res["matched"] else "-"
    print(f"  {opts:40} -> {'MATCH' if got else 'NO   '} @{off}")
    check(got == expected, label)

finish("T10")

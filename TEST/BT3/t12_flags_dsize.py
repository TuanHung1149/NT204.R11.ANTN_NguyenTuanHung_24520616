from common import event, check, finish
from rule_parser import parse_rule
from rule_matcher import match_rule

print("T12 - So khop TCP flags va dsize")


def run(ev, opts, sid):
    rule = parse_rule(f'alert tcp any any -> any 80 (msg:"t"; {opts} sid:{sid};)')
    return match_rule(rule, ev)


ev_pa = event(flags="PA", payload=b"X" * 150)
print(f"\n  [flags] event co flags=PA")
flag_cases = [
    ("flags:PA;", True, "khop chinh xac PA"),
    ("flags:AP;", True, "thu tu chu khong quan trong (AP = PA)"),
    ("flags:A;", False, "khop chinh xac 'A' that bai vi con co P"),
    ("flags:+A;", True, "'+' nghia la chua A"),
    ("flags:+PA;", True, "'+' chua ca P va A"),
    ("flags:*FS;", False, "'*' bat ky trong F,S -> khong co"),
    ("flags:*PF;", True, "'*' bat ky trong P,F -> co P"),
    ("flags:!R;", True, "'!' khong duoc co R"),
    ("flags:!P;", False, "'!' khong duoc co P nhung lai co"),
    ("flags:S;", False, "goi nay khong phai SYN"),
]
for i, (opts, expected, label) in enumerate(flag_cases, 1):
    res = run(ev_pa, opts, 1200 + i)
    print(f"      {opts:14} -> {'MATCH' if res['match'] else 'NO   '}")
    check(res["match"] == expected, label)

print(f"\n  [dsize] event co dsize=150")
dsize_cases = [
    ("dsize:150;", True, "bang dung 150"),
    ("dsize:100;", False, "khac 100"),
    ("dsize:>100;", True, "lon hon 100"),
    ("dsize:>150;", False, "khong lon hon chinh no"),
    ("dsize:<200;", True, "nho hon 200"),
    ("dsize:<150;", False, "khong nho hon chinh no"),
    ("dsize:>=150;", True, "lon hon hoac bang 150"),
    ("dsize:<=150;", True, "nho hon hoac bang 150"),
    ("dsize:100<>200;", True, "nam trong khoang 100-200"),
    ("dsize:10<>100;", False, "ngoai khoang 10-100"),
    ("dsize:150<>200;", True, "bien duoi tinh la nam trong (inclusive)"),
]
for i, (opts, expected, label) in enumerate(dsize_cases, 1):
    res = run(ev_pa, opts, 1300 + i)
    print(f"      {opts:18} -> {'MATCH' if res['match'] else 'NO   '}")
    check(res["match"] == expected, label)

# Ket hop flags + dsize + content
ev_syn = event(flags="S", payload=b"")
r = run(ev_syn, "flags:S; dsize:0;", 1400)
print(f"\n  goi SYN rong (flags:S; dsize:0) -> {'MATCH' if r['match'] else 'NO'}")
check(r["match"], "goi SYN khong payload khop flags:S va dsize:0")

r = run(ev_syn, "flags:S; dsize:>0;", 1401)
check(not r["match"], "goi SYN rong khong khop dsize:>0")
check(r["stage"] == "dsize", "bi loai dung o buoc dsize")

finish("T12")

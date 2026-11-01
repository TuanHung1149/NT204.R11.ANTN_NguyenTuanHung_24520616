from common import event, check, finish
from rule_parser import parse_rule
from rule_matcher import match_rule

print("T09 - content co nocase thi khong phan biet hoa thuong")

ev = event(payload=b"user=a' UnIoN SeLeCt 1,2,3-- FROM users")

with_nocase = parse_rule('alert tcp any any -> any 80 '
                         '(msg:"nocase"; content:"union select"; nocase; sid:900001;)')
no_nocase = parse_rule('alert tcp any any -> any 80 '
                       '(msg:"case sensitive"; content:"union select"; sid:900002;)')
exact_case = parse_rule('alert tcp any any -> any 80 '
                        '(msg:"dung hoa thuong"; content:"UnIoN SeLeCt"; sid:900003;)')

r1 = match_rule(with_nocase, ev)
r2 = match_rule(no_nocase, ev)
r3 = match_rule(exact_case, ev)

print(f"  payload: {ev['payload'].decode()}")
print(f"  content:\"union select\"; nocase  -> {'MATCH' if r1['match'] else 'NO MATCH'}")
print(f"  content:\"union select\"          -> {'MATCH' if r2['match'] else 'NO MATCH'}")
print(f"  content:\"UnIoN SeLeCt\"          -> {'MATCH' if r3['match'] else 'NO MATCH'}")

check(r1["match"], "co nocase -> match du khac hoa thuong")
check(not r2["match"], "khong nocase -> KHONG match khi khac hoa thuong")
check(r2["stage"] == "content", "truot o buoc content")
check(r3["match"], "khong nocase nhung dung hoa thuong -> match")

# Vi tri tim duoc phai la vi tri that trong payload goc
check(r1["matched"][0]["offset"] == 8, f"offset dung (={r1['matched'][0]['offset']})")
check(r1["matched"][0]["matched"] == "UnIoN SeLeCt", "tra ve doan khop nguyen ban goc")
print(f"  doan khop: '{r1['matched'][0]['matched']}' @offset={r1['matched'][0]['offset']}")

finish("T09")

from common import event, check, finish
from rule_parser import parse_rule
from rule_matcher import match_rule

print("T05 - Direction -> chi mot chieu, <> ca hai chieu")

# A = client 10.0.0.5:52133 , B = server 10.0.0.9:80
a_to_b = event(src_ip="10.0.0.5", src_port=52133, dst_ip="10.0.0.9", dst_port=80)
b_to_a = event(src_ip="10.0.0.9", src_port=80, dst_ip="10.0.0.5", dst_port=52133)

one_way = parse_rule('alert tcp 10.0.0.5 any -> 10.0.0.9 80 (msg:"oneway"; sid:500001;)')
two_way = parse_rule('alert tcp 10.0.0.5 any <> 10.0.0.9 80 (msg:"twoway"; sid:500002;)')

r1 = match_rule(one_way, a_to_b)
r2 = match_rule(one_way, b_to_a)
r3 = match_rule(two_way, a_to_b)
r4 = match_rule(two_way, b_to_a)

print(f"  rule '->' voi A->B : {'MATCH' if r1['match'] else 'NO MATCH'}")
print(f"  rule '->' voi B->A : {'MATCH' if r2['match'] else 'NO MATCH'} ({r2['reason'] or ''})")
print(f"  rule '<>' voi A->B : {'MATCH' if r3['match'] else 'NO MATCH'}")
print(f"  rule '<>' voi B->A : {'MATCH' if r4['match'] else 'NO MATCH'}")

check(r1["match"], "'->' khop chieu thuan A->B")
check(not r2["match"], "'->' KHONG khop chieu nguoc B->A")
check(r3["match"], "'<>' khop chieu A->B")
check(r4["match"], "'<>' khop ca chieu nguoc B->A")
check(r2["stage"] == "header", "chieu sai bi loai ngay o buoc header")

finish("T05")

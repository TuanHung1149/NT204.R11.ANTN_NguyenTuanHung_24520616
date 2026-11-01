from common import event, check, finish
from rule_parser import parse_rules
from rule_repository import build_repository

print("T06 - Indexer tra dung tap candidate theo protocol/port")

texts = [
    'alert tcp any any -> any 80 (msg:"tcp80"; sid:600001;)',
    'alert tcp any any -> any 443 (msg:"tcp443"; sid:600002;)',
    'alert udp any any -> any 53 (msg:"udp53"; sid:600003;)',
    'alert ip any any -> any any (msg:"ip any"; sid:600004;)',
    'alert tcp any 80 <> any any (msg:"tcp src80 bidir"; sid:600005;)',
    'alert tcp any any -> any 1:1024 (msg:"tcp range"; sid:600006;)',
]
repo = build_repository(parse_rules([{"text": t, "file": "mem", "lineno": i}
                                     for i, t in enumerate(texts, 1)]))
print(f"  tong rule: {len(repo.rules)} | bucket index: {repo.stats()['index_buckets']}")


def sids(ev):
    return [r["sid"] for r in repo.candidates(ev)]


c_tcp80 = sids(event(protocol="tcp", src_port=52133, dst_port=80))
c_udp53 = sids(event(protocol="udp", src_port=33333, dst_port=53))
c_tcp443 = sids(event(protocol="tcp", src_port=52133, dst_port=443))
c_srv = sids(event(protocol="tcp", src_port=80, dst_port=52133))

print(f"  TCP ->80          : {c_tcp80}")
print(f"  UDP ->53          : {c_udp53}")
print(f"  TCP ->443         : {c_tcp443}")
print(f"  TCP 80-> (server) : {c_srv}")

check(600001 in c_tcp80, "TCP->80 lay duoc rule tcp 80")
check(600002 not in c_tcp80, "TCP->80 khong lay rule tcp 443")
check(600003 not in c_tcp80, "TCP->80 khong lay rule UDP")
check(600004 in c_tcp80, "rule 'ip any' ap dung cho TCP")
check(600004 in c_udp53, "rule 'ip any' ap dung cho ca UDP")
check(600003 in c_udp53, "UDP->53 lay duoc rule udp 53")
check(600001 not in c_udp53, "UDP->53 khong lay rule TCP")
check(600005 in c_srv, "rule <> src 80 bat duoc chieu server->client")
check(600006 in c_tcp80, "rule port range nam trong candidate")
check(len(c_tcp443) < len(repo.rules), "indexer co loai bot rule, khong duyet toan bo")

finish("T06")

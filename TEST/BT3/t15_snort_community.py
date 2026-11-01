import os
from collections import Counter
from common import ROOT, check, finish
from rule_loader import load_rules
from rule_parser import parse_rules
from rule_repository import build_repository

print("T15 - Nap bo rule Snort community that (muc 2 cua de bai)")

rules_file = os.path.join(ROOT, "rules", "community.rules")
if not os.path.isfile(rules_file):
    print("  Bo qua: chua co rules/community.rules")
    finish("T15")

config = {
    "variables": {
        "HOME_NET": "10.0.0.0/8", "EXTERNAL_NET": "any",
        "HTTP_SERVERS": "10.0.0.0/8", "SQL_SERVERS": "10.0.0.0/8",
        "SMTP_SERVERS": "10.0.0.0/8", "DNS_SERVERS": "10.0.0.0/8",
        "TELNET_SERVERS": "10.0.0.0/8", "FTP_SERVERS": "10.0.0.0/8",
        "SSH_SERVERS": "10.0.0.0/8", "AIM_SERVERS": "any",
        "HTTP_PORTS": "[80,8080]", "SHELLCODE_PORTS": "any",
        "ORACLE_PORTS": "1521", "SSH_PORTS": "22", "FTP_PORTS": "21",
        "SIP_PORTS": "[5060,5061]", "FILE_DATA_PORTS": "[80,8080,110,143]",
        "GTP_PORTS": "[2123,2152,3386]",
    },
    "rule_files": [{"path": "rules/community.rules", "enabled": True}],
    "disabled_sids": [],
}

lines, _ = load_rules(config, base_dir=ROOT)
rules = parse_rules(lines)
repo = build_repository(rules)
st = repo.stats()

print(f"  rule doc duoc : {len(lines)}")
print(f"  valid         : {st['valid']}")
print(f"  unsupported   : {st['unsupported']}")
print(f"  invalid       : {st['invalid']}")

print("\n  Top ly do unsupported:")
for reason, count in Counter(r["reason"] for r in repo.unsupported).most_common(6):
    print(f"    {count:4}  {reason}")

check(len(lines) > 100, "doc duoc bo rule that (>100 rule)")
check(st["valid"] > 0, "co rule nam trong pham vi ho tro")
check(st["unsupported"] > 0, "rule ngoai pham vi bi danh dau unsupported")
check(st["invalid"] == 0, f"khong co rule bi parse sai (invalid={st['invalid']})")
check(all(r["reason"] for r in repo.unsupported), "moi rule unsupported deu co ly do")

# Khong rule unsupported nao lot vao tap danh gia
check(len(repo.rules) == st["valid"], "chi rule valid duoc dua vao danh gia")
check(all(r["sid"] is not None for r in repo.rules), "moi rule valid deu co sid")

# Indexer van chon duoc candidate tren bo rule lon
ev = {"protocol": "tcp", "src_ip": "1.2.3.4", "src_port": 40000,
      "dst_ip": "10.0.0.9", "dst_port": 80}
cands = repo.candidates(ev)
print(f"\n  candidate cho TCP->80: {len(cands)}/{st['valid']}")
check(len(cands) <= st["valid"], "indexer khong tra nhieu hon tong so rule")

finish("T15")

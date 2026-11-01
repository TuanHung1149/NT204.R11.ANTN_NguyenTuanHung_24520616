from common import ROOT, check, finish
from rule_loader import load_rules
from rule_parser import parse_rules
from rule_repository import build_repository

print("T03 - Keyword ngoai pham vi bi danh dau unsupported, khong crash")

config = {
    "variables": {},
    "rule_files": [{"path": "TEST/BT3/rules/unsupported.rules", "enabled": True}],
    "disabled_sids": [],
}
lines, _ = load_rules(config, base_dir=ROOT)
rules = parse_rules(lines)

for r in rules:
    print(f"  {r['status']:12} {r.get('msg') or '-':32} {r['reason'] or ''}")

unsupported = [r for r in rules if r["status"] == "unsupported"]
valid = [r for r in rules if r["status"] == "valid"]

check(len(unsupported) == 5, f"co 5 rule unsupported (thuc te {len(unsupported)})")
check(all(r["reason"] for r in unsupported), "moi rule unsupported deu co ly do")

reasons = " | ".join(r["reason"] for r in unsupported)
check("pcre" in reasons, "bat duoc pcre")
check("byte_test" in reasons, "bat duoc byte_test")
check("flowbits" in reasons, "bat duoc flowbits")
check("drop" in reasons, "bat duoc action drop")
check("icmp" in reasons, "bat duoc protocol icmp")

check(len(valid) == 1 and valid[0]["sid"] == 900206, "rule hop le con lai van nap duoc")

# Rule unsupported khong duoc dua vao tap danh gia
repo = build_repository(rules)
check(repo.stats()["valid"] == 1, "repository khong danh gia rule unsupported")

finish("T03")

from common import ROOT, check, finish
from rule_loader import load_rules
from rule_parser import parse_rules

print("T01 - Nap file rule co comment va dong trong")

config = {
    "variables": {},
    "rule_files": [{"path": "TEST/BT3/rules/valid_mixed.rules", "enabled": True}],
    "disabled_sids": [],
}
lines, warnings = load_rules(config, base_dir=ROOT)

print(f"  So dong dua sang parser: {len(lines)}")
for l in lines:
    print(f"    dong {l['lineno']}: {l['text'][:60]}...")

check(len(lines) == 3, "chi 3 rule duoc dua sang parser")
check(all(not l["text"].startswith("#") for l in lines), "khong co dong comment")
check(all(l["text"].strip() for l in lines), "khong co dong trong")
check(warnings == [], "khong co canh bao")

rules = parse_rules(lines)
check(all(r["status"] == "valid" for r in rules), "ca 3 rule deu valid")
check([r["sid"] for r in rules] == [900001, 900002, 900003], "sid dung thu tu")

finish("T01")

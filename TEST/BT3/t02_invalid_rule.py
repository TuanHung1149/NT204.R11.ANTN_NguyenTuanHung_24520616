from common import ROOT, check, finish
from rule_loader import load_rules
from rule_parser import parse_rules
from rule_repository import build_repository

print("T02 - Rule sai cu phap bi danh dau invalid, engine chay tiep")

config = {
    "variables": {},
    "rule_files": [{"path": "TEST/BT3/rules/bad_syntax.rules", "enabled": True}],
    "disabled_sids": [],
}
lines, _ = load_rules(config, base_dir=ROOT)
rules = parse_rules(lines)

for r in rules:
    print(f"  {r['status']:10} sid={str(r.get('sid')):8} {r.get('msg') or r['raw'][:35]}")
    if r["reason"]:
        print(f"             ly do: {r['reason']}")

invalid = [r for r in rules if r["status"] == "invalid"]
valid = [r for r in rules if r["status"] == "valid"]

check(len(invalid) == 5, f"co 5 rule invalid (thuc te {len(invalid)})")
check(all(r["reason"] for r in invalid), "moi rule invalid deu co ly do")
check(len(valid) == 2, "2 rule hop le van duoc nap")

# Engine van hoat dong binh thuong voi cac rule con lai
repo = build_repository(rules)
check(repo.stats()["valid"] == 2, "repository chi nhan rule valid")
check(repo.stats()["invalid"] == 5, "repository ghi nhan rule invalid")
check([r["sid"] for r in valid] == [900101, 900105], "rule truoc va sau loi deu nap duoc")

finish("T02")

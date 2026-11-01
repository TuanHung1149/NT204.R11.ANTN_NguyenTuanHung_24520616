from common import event, check, finish
from rule_parser import parse_rules
from rule_repository import build_repository
from evaluation_engine import EvaluationEngine

print("T13 - Mot event match dong thoi nhieu rule, khong dung o match dau tien")

texts = [
    'alert tcp any any -> any 80 (msg:"Co chu GET"; content:"GET"; sid:1301; rev:1;)',
    'alert tcp any any -> any 80 (msg:"Directory traversal"; content:"../"; sid:1302; rev:1;)',
    'alert tcp 10.0.0.0/8 any -> any any (msg:"Tu mang noi bo"; sid:1303; rev:1;)',
    'alert tcp any any -> any 80 (msg:"Goi PSH-ACK"; flags:PA; sid:1304; rev:1;)',
    'alert tcp any any -> any 443 (msg:"KHONG khop - sai port"; content:"GET"; sid:1305; rev:1;)',
    'alert udp any any -> any 80 (msg:"KHONG khop - sai proto"; sid:1306; rev:1;)',
    'alert tcp any any -> any 80 (msg:"KHONG khop - content vang"; content:"DELETE"; sid:1307; rev:1;)',
]
repo = build_repository(parse_rules([{"text": t, "file": "mem", "lineno": i}
                                     for i, t in enumerate(texts, 1)]))
engine = EvaluationEngine(repo)

ev = event(src_ip="10.0.0.5", dst_ip="10.0.0.9", dst_port=80, flags="PA",
           payload=b"GET /../../etc/passwd HTTP/1.1\r\n")
ctx = {"flow_id": "F123", "state": "ESTABLISHED", "to_server": True, "established": True}

detections = engine.evaluate(ev, ctx)
print(f"\n  Tong rule: {len(repo.rules)} | candidate: {len(repo.candidates(ev))} | match: {len(detections)}")
for d in detections:
    info = d["match_info"][0] if d["match_info"] else None
    extra = f' content="{info["content"]}"@{info["offset"]}' if info else ""
    print(f"    sid={d['sid']} {d['msg']}{extra}")

sids = sorted(d["sid"] for d in detections)
check(len(detections) >= 2, "co it nhat 2 rule cung match")
check(sids == [1301, 1302, 1303, 1304], f"dung 4 rule match (duoc {sids})")
check(1305 not in sids, "rule sai port khong match")
check(1306 not in sids, "rule sai protocol khong match")
check(1307 not in sids, "rule content vang khong match")

stats = engine.report()
print(f"  stats: {stats}")
check(stats["events"] == 1, "dem dung 1 event da danh gia")
check(stats["matches"] == 4, "dem dung 4 lan match")

finish("T13")

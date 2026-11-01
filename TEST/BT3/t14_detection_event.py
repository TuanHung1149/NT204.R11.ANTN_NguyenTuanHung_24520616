import json
from common import event, check, finish
from rule_parser import parse_rules
from rule_repository import build_repository
from evaluation_engine import EvaluationEngine
from detection_event import format_detection_event

print("T14 - Detection Event co du field theo muc 5 cua de bai")

text = ('alert tcp any any -> 10.0.0.0/8 80 (msg:"Directory traversal detected"; '
        'flow:to_server,established; content:"../"; classtype:web-application-attack; '
        'priority:1; sid:100001; rev:1;)')
repo = build_repository(parse_rules([{"text": text, "file": "local.rules", "lineno": 1}]))
engine = EvaluationEngine(repo)

ev = event(src_ip="10.0.0.5", src_port=52133, dst_ip="10.0.0.9", dst_port=80,
           flags="PA", payload=b"GET /../../etc/passwd HTTP/1.1\r\n",
           timestamp=1760000000.0, type="HTTP")
ctx = {"flow_id": "F123", "state": "ESTABLISHED", "to_server": True,
       "established": True, "application_protocol": "HTTP"}

detections = engine.evaluate(ev, ctx)
check(len(detections) == 1, "sinh ra 1 detection event")
d = detections[0]

print("\n  Detection Event (JSON):")
print(json.dumps(d, indent=2, ensure_ascii=False))

required = ["timestamp", "sid", "rev", "msg", "priority", "classtype",
            "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
            "application_protocol", "flow_id", "match_info"]
for field in required:
    check(field in d and d[field] is not None, f"co field '{field}'")

check(d["sid"] == 100001 and d["rev"] == 1, "sid/rev dung")
check(d["msg"] == "Directory traversal detected", "msg dung")
check(d["priority"] == 1 and d["classtype"] == "web-application-attack", "priority/classtype dung")
check(d["src_ip"] == "10.0.0.5" and d["src_port"] == 52133, "5-tuple: nguon dung")
check(d["dst_ip"] == "10.0.0.9" and d["dst_port"] == 80, "5-tuple: dich dung")
check(d["protocol"] == "tcp", "protocol dung")
check(d["application_protocol"] == "HTTP", "application_protocol dung")
check(d["flow_id"] == "F123", "flow_id dung")
check(d["match_info"][0]["content"] == "../", "match info co content da khop")
check(d["match_info"][0]["offset"] == 5, "match info co vi tri khop")

# Detection Event phai serialize duoc de bai sau ghi log
try:
    json.dumps(d)
    check(True, "serialize JSON duoc (san sang cho Alert/Logging)")
except TypeError as e:
    check(False, f"khong serialize duoc: {e}")

print("\n  Dang hien thi:")
print(format_detection_event(d))

finish("T14")

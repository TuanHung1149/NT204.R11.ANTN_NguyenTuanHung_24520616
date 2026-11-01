import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
RULES_DIR = os.path.join(HERE, "rules")
sys.path.insert(0, ROOT)

_failed = []


def rules_path(name):
    return os.path.join(RULES_DIR, name)


def event(**kw):
    # Event chuan hoa mac dinh, ghi de bang tham so
    ev = {
        "protocol": "tcp",
        "src_ip": "10.0.0.5", "src_port": 52133,
        "dst_ip": "10.0.0.9", "dst_port": 80,
        "flags": "PA", "payload": b"", "timestamp": 1760000000.0,
    }
    ev.update(kw)
    if "dsize" not in ev:
        ev["dsize"] = len(ev.get("payload") or b"")
    return ev


def check(condition, label):
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {label}")
    if not condition:
        _failed.append(label)


def finish(test_name):
    print()
    if _failed:
        print(f"=== {test_name} FAILED ({len(_failed)} loi) ===")
        sys.exit(1)
    print(f"=== {test_name} PASSED ===")

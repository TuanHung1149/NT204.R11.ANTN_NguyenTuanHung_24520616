import os
import json
from datetime import datetime

LEVEL_LOW = "LOW"
LEVEL_MEDIUM = "MEDIUM"
LEVEL_HIGH = "HIGH"
LEVEL_CRITICAL = "CRITICAL"

COLORS = {
    LEVEL_LOW: "\033[94m",
    LEVEL_MEDIUM: "\033[93m",
    LEVEL_HIGH: "\033[91m",
    LEVEL_CRITICAL: "\033[95m",
}
RESET = "\033[0m"

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "alerts.log")


def create_alert(level, attack_type, src_ip, dst_ip, description, details=None):
    return {
        "timestamp": datetime.now().isoformat(),
        "level": level,
        "attack_type": attack_type,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "description": description,
        "details": details or {},
    }


def print_alert(alert):
    color = COLORS.get(alert["level"], "")
    print(f"\n{color}[!] ALERT [{alert['level']}] - {alert['attack_type']}{RESET}")
    print(f"    Thời gian : {alert['timestamp']}")
    print(f"    Nguồn     : {alert['src_ip']}")
    print(f"    Đích      : {alert['dst_ip']}")
    print(f"    Mô tả     : {alert['description']}")
    if alert["details"]:
        for key, value in alert["details"].items():
            print(f"    {key}: {value}")


def log_alert(alert):
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(alert, ensure_ascii=False) + "\n")


def raise_alert(level, attack_type, src_ip, dst_ip, description, details=None):
    alert = create_alert(level, attack_type, src_ip, dst_ip, description, details)
    print_alert(alert)
    log_alert(alert)
    return alert

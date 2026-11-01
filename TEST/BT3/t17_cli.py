import os
import subprocess
import sys
from common import ROOT, check, finish

print("T17 - Chay main.py that bang dong lenh (CLI end-to-end)")

MAIN = os.path.join(ROOT, "main.py")
E2E = os.path.join(ROOT, "TEST", "BT3", "e2e.pcap")
BT1 = os.path.join(ROOT, "TEST", "test_traffic.pcap")


def run(pcap, cwd):
    r = subprocess.run([sys.executable, MAIN, "--pcap", pcap],
                       capture_output=True, text=True, cwd=cwd, timeout=120)
    return r


# --- 1. Chay tu trong thu muc du an ---
r1 = run(E2E, ROOT)
print(f"\n  [e2e.pcap] exit={r1.returncode}, {len(r1.stdout.splitlines())} dong output")
check(r1.returncode == 0, "chay xong khong loi")
check("Traceback" not in r1.stderr, "khong co exception")

for text, label in [
    ("Directory traversal detected", "in ra canh bao traversal"),
    ("SQL injection attempt", "in ra canh bao SQL injection"),
    ("Suspicious DNS query", "in ra canh bao DNS"),
    ('matched content="../"', "in ra noi dung da khop"),
    ("FLOW SUMMARY", "in bang tong ket flow"),
    ("CORE ENGINE", "in bang tong ket engine"),
    ("state     : CLOSED", "flow TCP ket thuc CLOSED"),
]:
    check(text in r1.stdout, label)

# --- 2. Cac detector cua bai 1 van hoat dong ---
r2 = run(BT1, ROOT)
print(f"  [test_traffic.pcap] exit={r2.returncode}")
check(r2.returncode == 0, "pcap bai 1 chay xong khong loi")
for text, label in [("PORT_SCAN", "detector port scan"),
                    ("BRUTE_FORCE", "detector brute force"),
                    ("DNS_TUNNELING", "detector DNS tunneling")]:
    check(text in r2.stdout, f"{label} van canh bao")

# --- 3. Chay tu thu muc KHAC (thay cham co the chay kieu nay) ---
r3 = run(E2E, "/")
print(f"  [chay tu thu muc /] exit={r3.returncode}")
check(r3.returncode == 0, "chay duoc tu thu muc bat ky")
check("CORE ENGINE" in r3.stdout, "ket qua giong nhau du chay o dau")
check("FileNotFoundError" not in r3.stderr, "khong loi duong dan config")

# --- 4. Canh bao nap rule duoc in ra (muc 4.1) ---
check("canh bao khi nap rule" in r1.stdout, "in canh bao khi nap rule")

# --- 5. So detection in ra khop so dem duoc ---
printed = sum(1 for line in r1.stdout.splitlines() if line.startswith("[1000"))
summary = [l for l in r1.stdout.splitlines() if "detection event" in l]
print(f"  detection in ra: {printed} | dong tong ket: {summary}")
check(printed > 0, "co in detection event")
check(str(printed) in summary[0], "so dem trong tong ket khop so dong da in")

finish("T17")

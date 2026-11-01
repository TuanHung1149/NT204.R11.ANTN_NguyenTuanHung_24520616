import os
import sys
import signal
from scapy.all import rdpcap
from capture import start_capture, extract_packet_info
from parsers import parse_packet
from detectors import PortScanDetector, BruteForceDetector, DNSAnomalyDetector, SYNFloodDetector
from detection_event import format_detection_event
from pipeline import IDSPipeline
from alert import RESET

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOAD_LOG = os.path.join(BASE_DIR, "logs", "rule_load.log")

pipeline = IDSPipeline()
port_scan = PortScanDetector()
brute_force = BruteForceDetector()
dns_anomaly = DNSAnomalyDetector()
syn_flood = SYNFloodDetector()


def process_packet(packet):
    # Bai 1: cac detector dua tren nguong, dung du lieu tho
    info = extract_packet_info(packet)
    if info:
        src = f"{info['src_ip']}:{info['src_port']}" if info["src_port"] else info["src_ip"]
        dst = f"{info['dst_ip']}:{info['dst_port']}" if info["dst_port"] else info["dst_ip"]
        print(f"[{pipeline.packet_count + 1}] {info['protocol']} {src} -> {dst}")

        port_scan.analyze(info)
        brute_force.analyze(info)
        syn_flood.analyze(info)
        parsed = parse_packet(packet)
        if parsed:
            dns_anomaly.analyze(parsed)

    # Bai 2 + 3: day chuyen chinh -> Detection Event
    for detection in pipeline.process(packet):
        print(format_detection_event(detection))


def print_load_warnings(limit=20):
    # Muc 4.1: loi mot rule khong lam dung viec nap, nhung phai bao ra
    warnings = pipeline.engine.warnings
    if not warnings:
        return

    os.makedirs(os.path.dirname(LOAD_LOG), exist_ok=True)
    with open(LOAD_LOG, "w", encoding="utf-8") as f:
        f.write("\n".join(warnings) + "\n")

    print(f"[!] {len(warnings)} canh bao khi nap rule:")
    for w in warnings[:limit]:
        print(f"    - {w}")
    if len(warnings) > limit:
        print(f"    ... con {len(warnings) - limit} canh bao nua (xem {LOAD_LOG})")
    print()


def print_flow_summary():
    flows = pipeline.flow_tracker.all_flows()
    print(f"\n{'=' * 60}")
    print(f"  FLOW SUMMARY - {len(flows)} flow")
    print("=" * 60)
    for f in flows:
        d = f.to_dict()
        print(f"\n  flow_id   : {d['flow_id']} ({d['protocol']}, {d['application_protocol'] or '-'})")
        print(f"  {d['endpoint_a']} <-> {d['endpoint_b']}")
        print(f"  state     : {d['state']} | duration: {d['duration']}s")
        print(f"  packets   : {d['packet_count']} (fwd {d['forward']['packets']} / bwd {d['backward']['packets']})")
        print(f"  bytes     : {d['byte_count']}")
        if d["protocol"] == "tcp":
            fl = d["tcp_flags"]
            print(f"  tcp flags : SYN={fl['SYN']} ACK={fl['ACK']} FIN={fl['FIN']} RST={fl['RST']}")


def print_engine_summary():
    r = pipeline.report()
    print(f"\n{'=' * 60}")
    print(f"  CORE ENGINE - {r['detections']} detection event")
    print("=" * 60)
    print(f"  rule: {r['valid']} valid / {r['invalid']} invalid / {r['unsupported']} unsupported")
    print(f"  event danh gia : {r['events']}")
    print(f"  candidate rule : {r['candidates']} (bo qua nho index: {r['rules_skipped']})")
    print(f"  so lan match   : {r['matches']}")
    if r["skipped"]:
        print(f"  goi bi bo qua  : {r['skipped']}")


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "--pcap":
        print(f"Đọc file: {sys.argv[2]}\n")
        print_load_warnings()
        for packet in rdpcap(sys.argv[2]):
            process_packet(packet)
        print(f"\nXong. Đã xử lý {pipeline.packet_count} gói tin.")
        print_flow_summary()
        print_engine_summary()
        return

    interface = sys.argv[1] if len(sys.argv) > 1 else None
    bpf_filter = sys.argv[2] if len(sys.argv) > 2 else None

    print("=" * 60)
    print("  IDS - Hệ thống phát hiện xâm nhập")
    print("=" * 60)
    print(f"  Interface : {interface or 'mặc định'}")
    print(f"  Filter    : {bpf_filter or 'không'}")
    print("  Pipeline  : Capture -> Decoder -> Preprocessor -> Flow Tracker -> Core Engine")
    print(f"  Rule      : {pipeline.engine.repository.stats()['valid']} rule da nap")
    print("  Detector  : Port Scan, Brute Force, DNS Anomaly, SYN Flood")
    print("=" * 60)
    print("Đang lắng nghe... (Ctrl+C để dừng)\n")
    print_load_warnings()

    def on_exit(s, f):
        print(f"\n\nDừng. Đã xử lý {pipeline.packet_count} gói tin.{RESET}")
        print_flow_summary()
        print_engine_summary()
        sys.exit(0)

    signal.signal(signal.SIGINT, on_exit)
    start_capture(interface=interface, packet_callback=process_packet, bpf_filter=bpf_filter)


if __name__ == "__main__":
    main()

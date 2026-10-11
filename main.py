import sys
import signal
from scapy.all import rdpcap
from capture import start_capture, extract_packet_info
from parsers import parse_packet
from detectors import PortScanDetector, BruteForceDetector, DNSAnomalyDetector, SYNFloodDetector
from decoder import decode_event
from preprocessor import preprocess
from flow_tracker import FlowTracker
from alert import RESET

port_scan = PortScanDetector()
brute_force = BruteForceDetector()
dns_anomaly = DNSAnomalyDetector()
syn_flood = SYNFloodDetector()
flow_tracker = FlowTracker()

packet_count = 0


def process_packet(packet):
    global packet_count
    packet_count += 1

    info = extract_packet_info(packet)
    if not info:
        return

    proto = info["protocol"]
    src = f"{info['src_ip']}:{info['src_port']}" if info["src_port"] else info["src_ip"]
    dst = f"{info['dst_ip']}:{info['dst_port']}" if info["dst_port"] else info["dst_ip"]
    print(f"[{packet_count}] {proto} {src} -> {dst}")

    parsed = parse_packet(packet)

    # Bài 1: phát hiện tấn công
    port_scan.analyze(info)
    brute_force.analyze(info)
    syn_flood.analyze(info)
    if parsed:
        dns_anomaly.analyze(parsed)

    # Bài 2: pipeline Decoder -> Preprocessor -> Flow Tracker
    event = dict(info)
    if parsed and parsed.get("type"):
        event["type"] = parsed["type"]
        if "path" in parsed:
            event["path"] = parsed["path"]
        if "headers" in parsed:
            event["headers"] = parsed["headers"]

    event = decode_event(event)
    event = preprocess(event)
    if event.get("processing_action") != "drop":
        flow_tracker.process(event)


def print_flow_summary():
    flows = flow_tracker.all_flows()
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
        if d['protocol'] == 'tcp':
            fl = d['tcp_flags']
            print(f"  tcp flags : SYN={fl['SYN']} ACK={fl['ACK']} FIN={fl['FIN']} RST={fl['RST']}")


def main():
    # Chế độ đọc file pcap: python3 main.py --pcap file.pcap
    if len(sys.argv) >= 3 and sys.argv[1] == "--pcap":
        pcap_file = sys.argv[2]
        print(f"Đọc file: {pcap_file}\n")
        packets = rdpcap(pcap_file)
        for pkt in packets:
            process_packet(pkt)
        print(f"\nXong. Đã xử lý {packet_count} gói tin.")
        print_flow_summary()
        return

    # Chế độ live capture
    interface = sys.argv[1] if len(sys.argv) > 1 else None
    bpf_filter = sys.argv[2] if len(sys.argv) > 2 else None

    print("=" * 60)
    print("  IDS - Hệ thống phát hiện xâm nhập")
    print("=" * 60)
    print(f"  Interface : {interface or 'mặc định'}")
    print(f"  Filter    : {bpf_filter or 'không'}")
    print(f"  Pipeline  : Capture -> Decoder -> Preprocessor -> Flow Tracker")
    print(f"  Detector  : Port Scan, Brute Force, DNS Anomaly, SYN Flood")
    print("=" * 60)
    print("Đang lắng nghe... (Ctrl+C để dừng)\n")

    def on_exit(s, f):
        print(f"\n\nDừng. Đã xử lý {packet_count} gói tin.{RESET}")
        print_flow_summary()
        sys.exit(0)

    signal.signal(signal.SIGINT, on_exit)

    start_capture(
        interface=interface,
        packet_callback=process_packet,
        bpf_filter=bpf_filter,
    )


if __name__ == "__main__":
    main()

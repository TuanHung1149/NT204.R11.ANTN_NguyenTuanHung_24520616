import json
import os
from scapy.all import rdpcap
from common import ROOT, check, finish
from pipeline import IDSPipeline

print("T16 - End-to-end: file pcap -> ca day chuyen -> Detection Event")

PCAP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "e2e.pcap")
packets = rdpcap(PCAP)
pipe = IDSPipeline()
pipe.process_pcap(PCAP)

print(f"\n  goi doc duoc : {pipe.packet_count}")
print(f"  goi bo qua   : {pipe.skipped}")
print(f"  detection    : {len(pipe.detections)}")

# --- 1. Chay het pcap, khong crash ---
check(pipe.packet_count == 13, "xu ly du 13 goi")
check(len(pipe.detections) > 0, "co sinh detection event")

# --- 2. Goi ARP (khong phai IP) bi bo qua em, khong lam dung chuong trinh ---
check(len(pipe.skipped) == 1, "dung 1 goi bi bo qua")
check(pipe.skipped[0][0] == 1 and "IP" in pipe.skipped[0][1], "goi ARP bi bo qua dung ly do")

# --- 3. Goi hong khong lam dung pipeline ---
class Broken:
    def haslayer(self, _):
        raise ValueError("goi hong co chu y")

before = len(pipe.detections)
pipe.process(Broken())
check(len(pipe.skipped) == 2, "goi hong duoc ghi nhan la bo qua")
check(len(pipe.detections) == before, "goi hong khong sinh detection")
after = pipe.process(packets[4])
check(isinstance(after, list), "pipeline van chay binh thuong sau goi hong")
print(f"  sau goi hong : skipped={pipe.skipped[-1]}")

# --- 4. ACK rong co padding Ethernet -> dsize phai = 0 ---
ack = pipe.build_event(packets[3])
print(f"\n  ACK co padding: dsize={ack['dsize']} (size goi={ack['size']})")
check(ack["dsize"] == 0, "padding Ethernet khong bi tinh vao dsize")

# --- 5+6. Directory traversal: ban tho va ban MA HOA percent ---
trav = pipe.detections_by_sid(100001)
fields = sorted(d["match_info"][0]["field"] for d in trav)
print(f"\n  sid 100001 khop {len(trav)} lan, tim thay trong: {fields}")
check(len(trav) == 2, "bat duoc ca 2 goi traversal")
check("payload" in fields, "ban tho khop trong payload")
check("app_data" in fields, "ban ma hoa khop trong app_data (nho Decoder bai 2)")
check(all(d["match_info"][0]["content"] == "../" for d in trav), "content khop la '../'")

# --- 7. SQL injection chu thuong -> nocase ---
sqli = pipe.detections_by_sid(100002)
check(len(sqli) == 1, "bat duoc 1 goi SQL injection")
check(sqli[0]["match_info"][0]["matched"].lower() == "union select", "nocase khop chu thuong")
print(f"  sid 100002 khop: '{sqli[0]['match_info'][0]['matched']}'")

# --- 8. Goi tra ve lon -> dsize:>100 ---
large = pipe.detections_by_sid(100005)
check(len(large) == 1, "bat duoc 1 goi payload lon (dsize>100)")

# --- 9. DNS qua UDP -> app_data ---
dns = pipe.detections_by_sid(100007)
check(len(dns) == 1, "bat duoc 1 DNS query xau")
check(dns[0]["protocol"] == "udp", "detection DNS la UDP")
check(dns[0]["application_protocol"] == "DNS", "nhan dien application_protocol = DNS")
print(f"  sid 100007: {dns[0]['protocol']}/{dns[0]['application_protocol']}")

# --- 10. Cac flow khong bi gop nham ---
flows = {f.flow_id: f for f in pipe.flow_tracker.all_flows()}
print(f"\n  so flow: {len(flows)}")
for f in flows.values():
    d = f.to_dict()
    print(f"    {d['protocol']}/{d['application_protocol'] or '-':4} {d['endpoint_a']}<->{d['endpoint_b']} state={d['state']} pkt={d['packet_count']}")
check(len(flows) == 3, "tach dung 3 flow rieng biet")

# --- 11. Vong doi flow TCP: handshake -> du lieu -> dong ---
tcp_flow = next(f for f in flows.values() if f.endpoint_b == ("10.0.0.9", 80))
check(tcp_flow.state == "CLOSED", "flow TCP ket thuc o trang thai CLOSED")
check(tcp_flow.application_protocol == "HTTP", "flow TCP nhan dien duoc HTTP")
check(tcp_flow.packet_count == 9, f"dem du 9 goi trong flow (duoc {tcp_flow.packet_count})")
check(tcp_flow.fwd_packets == 6 and tcp_flow.bwd_packets == 3, "dem dung hai chieu")
check(tcp_flow.syn_count == 2 and tcp_flow.fin_count == 2, "dem dung co SYN/FIN")

# --- 12. Flow UDP DNS hai chieu ---
udp_flow = next(f for f in flows.values() if f.protocol == "udp")
check(udp_flow.packet_count == 2, "flow DNS co 2 goi")
check(udp_flow.fwd_packets == 1 and udp_flow.bwd_packets == 1, "DNS query va response cung 1 flow")

# --- 13. Detection Event du field va ghi log duoc ---
d = trav[0]
for field in ["timestamp", "sid", "rev", "msg", "priority", "classtype", "src_ip",
              "src_port", "dst_ip", "dst_port", "protocol", "flow_id", "match_info"]:
    check(d.get(field) is not None, f"detection co field '{field}'")
check(d["flow_id"] == tcp_flow.flow_id, "flow_id trong detection khop flow that")
try:
    json.dumps(pipe.detections)
    check(True, "toan bo detection serialize JSON duoc")
except TypeError as e:
    check(False, f"khong serialize duoc: {e}")

# --- 14. Thong ke nhat quan ---
r = pipe.report()
print(f"\n  report: {r}")
check(r["matches"] == len(pipe.detections), "so lan match khop so detection")
check(r["candidates"] >= r["matches"], "candidate luon >= so match")
check(r["invalid"] == 0 and r["valid"] > 0, "rule nap sach")

finish("T16")

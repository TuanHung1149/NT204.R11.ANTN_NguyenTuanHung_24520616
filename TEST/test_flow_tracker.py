import sys
sys.path.insert(0, "..")

from flow_tracker import FlowTracker, make_flow_id


def _pkt(sip, sp, dip, dp, proto="tcp", flags="", size=60, ptype=None):
    e = {"src_ip": sip, "src_port": sp, "dst_ip": dip, "dst_port": dp,
         "protocol": proto, "flags": flags, "size": size}
    if ptype:
        e["type"] = ptype
    return e


def test_t07_tcp_handshake():
    # T07: SYN -> SYN/ACK -> ACK = 1 flow, state ESTABLISHED
    ft = FlowTracker()
    ft.process(_pkt("10.0.0.1", 5000, "10.0.0.2", 80, flags="S"), 1.0)
    ft.process(_pkt("10.0.0.2", 80, "10.0.0.1", 5000, flags="SA"), 1.1)
    f = ft.process(_pkt("10.0.0.1", 5000, "10.0.0.2", 80, flags="A"), 1.2)
    assert f.state == "ESTABLISHED"
    assert len(ft.flows) == 1
    print("[PASS] T07 - TCP handshake ESTABLISHED")


def test_t08_bidirectional():
    # T08: A->B và B->A cùng 5-tuple đảo chiều -> cùng flow_id, đúng direction
    ft = FlowTracker()
    f1 = ft.process(_pkt("10.0.0.1", 5000, "10.0.0.2", 80, flags="S"), 1.0)
    f2 = ft.process(_pkt("10.0.0.2", 80, "10.0.0.1", 5000, flags="SA"), 1.1)
    assert f1.flow_id == f2.flow_id
    assert len(ft.flows) == 1
    assert f2.fwd_packets == 1 and f2.bwd_packets == 1
    print("[PASS] T08 - Bidirectional same flow")


def test_t09_tcp_close():
    # T09: FIN hoặc RST -> flow chuyển CLOSED/RESET
    ft = FlowTracker()
    ft.process(_pkt("1.1.1.1", 1, "2.2.2.2", 80, flags="S"), 1.0)
    f = ft.process(_pkt("2.2.2.2", 80, "1.1.1.1", 1, flags="R"), 2.0)
    assert f.state == "RESET"
    assert len(ft.flows) == 0  # đã loại khỏi active table
    assert len(ft.closed_flows) == 1
    print("[PASS] T09 - TCP close RESET")


def test_t10_udp_flow():
    # T10: DNS UDP hai chiều -> 1 UDP flow, packet/byte count đúng
    ft = FlowTracker()
    ft.process(_pkt("10.0.0.1", 5353, "8.8.8.8", 53, proto="udp", size=70, ptype="DNS"), 1.0)
    f = ft.process(_pkt("8.8.8.8", 53, "10.0.0.1", 5353, proto="udp", size=120, ptype="DNS"), 1.1)
    assert len(ft.flows) == 1
    assert f.packet_count == 2
    assert f.byte_count == 190
    assert f.application_protocol == "DNS"
    print("[PASS] T10 - UDP query/response flow")


def test_t11_concurrent_flows():
    # T11: >=2 flow endpoint/port khác nhau -> không gộp nhầm
    ft = FlowTracker()
    ft.process(_pkt("10.0.0.1", 5000, "10.0.0.2", 80, flags="S"), 1.0)
    ft.process(_pkt("10.0.0.1", 5001, "10.0.0.3", 443, flags="S"), 1.0)
    ft.process(_pkt("10.0.0.5", 6000, "10.0.0.2", 22, flags="S"), 1.0)
    assert len(ft.flows) == 3
    print("[PASS] T11 - Concurrent flows not merged")


def test_t12_idle_timeout():
    # T12: flow không có packet mới quá timeout -> hết hạn, loại khỏi active table
    ft = FlowTracker(udp_timeout=60)
    ft.process(_pkt("10.0.0.1", 5353, "8.8.8.8", 53, proto="udp", size=70), 1000.0)
    assert len(ft.flows) == 1
    expired = ft.expire_flows(1000.0 + 61)
    assert len(expired) == 1
    assert len(ft.flows) == 0
    assert expired[0].state == "CLOSED"
    print("[PASS] T12 - Idle timeout expiry")


def test_t13_statistics():
    # T13: nhiều packet hai chiều -> packet/byte/flag counters và duration đúng
    ft = FlowTracker()
    ft.process(_pkt("10.0.0.1", 5000, "10.0.0.2", 80, flags="S", size=60), 1.0)
    ft.process(_pkt("10.0.0.2", 80, "10.0.0.1", 5000, flags="SA", size=60), 1.5)
    ft.process(_pkt("10.0.0.1", 5000, "10.0.0.2", 80, flags="A", size=52), 2.0)
    f = ft.process(_pkt("10.0.0.1", 5000, "10.0.0.2", 80, flags="PA", size=200), 2.5)

    assert f.packet_count == 4
    assert f.byte_count == 372
    assert f.fwd_packets == 3 and f.bwd_packets == 1
    assert f.syn_count == 2 and f.ack_count == 3
    assert f.duration() == 1.5
    print("[PASS] T13 - Statistics counters correct")


if __name__ == "__main__":
    test_t07_tcp_handshake()
    test_t08_bidirectional()
    test_t09_tcp_close()
    test_t10_udp_flow()
    test_t11_concurrent_flows()
    test_t12_idle_timeout()
    test_t13_statistics()
    print("\n=== Flow tracker tests PASSED ===")

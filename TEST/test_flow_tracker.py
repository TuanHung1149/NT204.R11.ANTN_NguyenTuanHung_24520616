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


if __name__ == "__main__":
    test_t07_tcp_handshake()
    test_t08_bidirectional()
    test_t09_tcp_close()
    print("\n=== Flow tracker tests PASSED ===")

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


if __name__ == "__main__":
    test_t07_tcp_handshake()
    print("\n=== Flow tracker tests PASSED ===")

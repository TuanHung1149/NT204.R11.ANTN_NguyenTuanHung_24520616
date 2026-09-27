import sys
sys.path.insert(0, "..")

from detectors import PortScanDetector, BruteForceDetector, SYNFloodDetector, DNSAnomalyDetector


def test_port_scan():
    detector = PortScanDetector(threshold=5, time_window=60)

    # Gửi 4 port khác nhau → chưa alert
    for port in range(1, 5):
        result = detector.analyze({
            "src_ip": "192.168.1.100", "dst_ip": "10.0.0.1",
            "dst_port": port, "protocol": "TCP", "flags": "S",
        })
        assert result is None

    # Port thứ 5 → alert!
    result = detector.analyze({
        "src_ip": "192.168.1.100", "dst_ip": "10.0.0.1",
        "dst_port": 5, "protocol": "TCP", "flags": "S",
    })
    assert result is not None
    assert result["attack_type"] == "PORT_SCAN"
    print("[PASS] test_port_scan")


def test_brute_force():
    detector = BruteForceDetector(threshold=3, time_window=60)

    for _ in range(2):
        result = detector.analyze({
            "src_ip": "192.168.1.100", "dst_ip": "10.0.0.1",
            "dst_port": 22, "protocol": "TCP", "flags": "S",
        })
        assert result is None

    # Lần thứ 3 → alert
    result = detector.analyze({
        "src_ip": "192.168.1.100", "dst_ip": "10.0.0.1",
        "dst_port": 22, "protocol": "TCP", "flags": "S",
    })
    assert result is not None
    assert result["attack_type"] == "BRUTE_FORCE"
    print("[PASS] test_brute_force")


def test_syn_flood():
    detector = SYNFloodDetector(threshold=5, time_window=60)

    for i in range(4):
        result = detector.analyze({
            "src_ip": f"192.168.1.{i}", "dst_ip": "10.0.0.1",
            "dst_port": 80, "protocol": "TCP", "flags": "S",
        })
        assert result is None

    result = detector.analyze({
        "src_ip": "192.168.1.99", "dst_ip": "10.0.0.1",
        "dst_port": 80, "protocol": "TCP", "flags": "S",
    })
    assert result is not None
    assert result["attack_type"] == "SYN_FLOOD"
    print("[PASS] test_syn_flood")


def test_dns_tunneling():
    detector = DNSAnomalyDetector(domain_length_threshold=30)

    # Domain ngắn → không alert
    result = detector.analyze({
        "type": "DNS", "is_query": True,
        "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8",
        "queries": [{"name": "google.com"}],
    })
    assert result is None

    # Domain dài bất thường → alert
    long_domain = "a" * 60 + ".evil.com"
    result = detector.analyze({
        "type": "DNS", "is_query": True,
        "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8",
        "queries": [{"name": long_domain}],
    })
    assert result is not None
    assert any(a["attack_type"] == "DNS_TUNNELING" for a in result)
    print("[PASS] test_dns_tunneling")


if __name__ == "__main__":
    test_port_scan()
    test_brute_force()
    test_syn_flood()
    test_dns_tunneling()
    print("\n=== All detector tests PASSED ===")

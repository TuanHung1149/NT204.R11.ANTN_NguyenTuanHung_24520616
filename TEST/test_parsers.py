import sys
sys.path.insert(0, "..")

from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, Ether
from parsers import parse_tcp, parse_udp, parse_dns, parse_http, parse_packet


def test_parse_tcp():
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="S")
    result = parse_tcp(pkt)
    assert result is not None
    assert result["type"] == "TCP"
    assert result["src_ip"] == "10.0.0.1"
    assert result["dst_port"] == 80
    assert "S" in result["flags"]
    print("[PASS] test_parse_tcp")


def test_parse_udp():
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=53)
    result = parse_udp(pkt)
    assert result is not None
    assert result["type"] == "UDP"
    assert result["dst_port"] == 53
    print("[PASS] test_parse_udp")


def test_parse_dns():
    pkt = IP(src="10.0.0.1", dst="8.8.8.8") / UDP() / DNS(rd=1, qd=DNSQR(qname="example.com"))
    result = parse_dns(pkt)
    assert result is not None
    assert result["type"] == "DNS"
    assert result["is_query"] is True
    assert len(result["queries"]) == 1
    assert "example" in result["queries"][0]["name"]
    print("[PASS] test_parse_dns")


def test_parse_http():
    http_payload = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(load=http_payload)
    result = parse_http(pkt)
    assert result is not None
    assert result["type"] == "HTTP"
    assert result["method"] == "GET"
    assert result["path"] == "/index.html"
    assert result["headers"]["host"] == "example.com"
    print("[PASS] test_parse_http")


def test_parse_packet_auto():
    # TCP thuần → trả về TCP
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=443)
    result = parse_packet(pkt)
    assert result["type"] == "TCP"

    # DNS → trả về DNS
    pkt = IP() / UDP() / DNS(rd=1, qd=DNSQR(qname="google.com"))
    result = parse_packet(pkt)
    assert result["type"] == "DNS"
    print("[PASS] test_parse_packet_auto")


if __name__ == "__main__":
    test_parse_tcp()
    test_parse_udp()
    test_parse_dns()
    test_parse_http()
    test_parse_packet_auto()
    print("\n=== All parser tests PASSED ===")

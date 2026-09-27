import time
from collections import defaultdict
from alert import raise_alert, LEVEL_HIGH, LEVEL_MEDIUM, LEVEL_CRITICAL


class PortScanDetector:
    # Nếu 1 IP kết nối >= threshold port khác nhau trong time_window giây → port scan

    def __init__(self, threshold=20, time_window=10):
        self.threshold = threshold
        self.time_window = time_window
        self.connections = defaultdict(list)

    def analyze(self, packet_info):
        if not packet_info or packet_info.get("dst_port") is None:
            return None

        src_ip = packet_info["src_ip"]
        dst_port = packet_info["dst_port"]
        dst_ip = packet_info["dst_ip"]
        now = time.time()

        self.connections[src_ip].append((dst_port, now))
        self.connections[src_ip] = [
            (port, ts) for port, ts in self.connections[src_ip]
            if now - ts <= self.time_window
        ]

        unique_ports = set(port for port, _ in self.connections[src_ip])

        if len(unique_ports) >= self.threshold:
            alert = raise_alert(
                LEVEL_HIGH, "PORT_SCAN", src_ip, dst_ip,
                f"Phát hiện quét cổng: {len(unique_ports)} port trong {self.time_window}s",
                {"ports_scanned": len(unique_ports), "ports": sorted(unique_ports)[:20]},
            )
            self.connections[src_ip] = []
            return alert
        return None


class BruteForceDetector:
    # Quá nhiều SYN đến cùng 1 port dịch vụ (SSH, FTP...) → brute force

    WATCHED_PORTS = {22: "SSH", 21: "FTP", 23: "Telnet", 3389: "RDP", 80: "HTTP", 443: "HTTPS"}

    def __init__(self, threshold=15, time_window=30):
        self.threshold = threshold
        self.time_window = time_window
        self.attempts = defaultdict(list)

    def analyze(self, packet_info):
        if not packet_info or packet_info.get("dst_port") is None:
            return None

        dst_port = packet_info["dst_port"]
        if dst_port not in self.WATCHED_PORTS:
            return None

        flags = packet_info.get("flags", "")
        if "S" not in flags:
            return None

        src_ip = packet_info["src_ip"]
        dst_ip = packet_info["dst_ip"]
        now = time.time()
        key = (src_ip, dst_port)

        self.attempts[key].append(now)
        self.attempts[key] = [ts for ts in self.attempts[key] if now - ts <= self.time_window]

        if len(self.attempts[key]) >= self.threshold:
            service = self.WATCHED_PORTS[dst_port]
            alert = raise_alert(
                LEVEL_CRITICAL, "BRUTE_FORCE", src_ip, dst_ip,
                f"Brute force {service} (port {dst_port}): {len(self.attempts[key])} lần trong {self.time_window}s",
                {"service": service, "port": dst_port, "attempts": len(self.attempts[key])},
            )
            self.attempts[key] = []
            return alert
        return None


class DNSAnomalyDetector:
    # Domain quá dài → DNS tunneling | Quá nhiều query → DNS flood

    def __init__(self, domain_length_threshold=50, query_threshold=50, time_window=10):
        self.domain_length_threshold = domain_length_threshold
        self.query_threshold = query_threshold
        self.time_window = time_window
        self.query_count = defaultdict(list)

    def analyze(self, parsed_info):
        if not parsed_info or parsed_info.get("type") != "DNS":
            return None
        if not parsed_info.get("is_query"):
            return None

        src_ip = parsed_info.get("src_ip", "unknown")
        dst_ip = parsed_info.get("dst_ip", "unknown")
        alerts = []

        for query in parsed_info.get("queries", []):
            domain = query.get("name", "")
            if len(domain) > self.domain_length_threshold:
                alerts.append(raise_alert(
                    LEVEL_HIGH, "DNS_TUNNELING", src_ip, dst_ip,
                    f"Nghi ngờ DNS tunneling: domain dài {len(domain)} ký tự",
                    {"domain": domain[:80], "length": len(domain)},
                ))

        now = time.time()
        self.query_count[src_ip].append(now)
        self.query_count[src_ip] = [
            ts for ts in self.query_count[src_ip] if now - ts <= self.time_window
        ]

        if len(self.query_count[src_ip]) >= self.query_threshold:
            alerts.append(raise_alert(
                LEVEL_MEDIUM, "DNS_FLOOD", src_ip, dst_ip,
                f"DNS flood: {len(self.query_count[src_ip])} queries trong {self.time_window}s",
                {"query_count": len(self.query_count[src_ip])},
            ))
            self.query_count[src_ip] = []

        return alerts if alerts else None


class SYNFloodDetector:
    # Quá nhiều gói SYN thuần đến 1 IP → SYN flood (DDoS)

    def __init__(self, threshold=100, time_window=10):
        self.threshold = threshold
        self.time_window = time_window
        self.syn_packets = defaultdict(list)

    def analyze(self, packet_info):
        if not packet_info or packet_info.get("protocol") != "TCP":
            return None

        if packet_info.get("flags", "") != "S":
            return None

        src_ip = packet_info["src_ip"]
        dst_ip = packet_info["dst_ip"]
        now = time.time()

        self.syn_packets[dst_ip].append((src_ip, now))
        self.syn_packets[dst_ip] = [
            (ip, ts) for ip, ts in self.syn_packets[dst_ip]
            if now - ts <= self.time_window
        ]

        if len(self.syn_packets[dst_ip]) >= self.threshold:
            unique_sources = set(ip for ip, _ in self.syn_packets[dst_ip])
            alert = raise_alert(
                LEVEL_CRITICAL, "SYN_FLOOD", f"{len(unique_sources)} IPs", dst_ip,
                f"SYN flood: {len(self.syn_packets[dst_ip])} SYN packets trong {self.time_window}s",
                {"total_syn": len(self.syn_packets[dst_ip]), "unique_sources": len(unique_sources)},
            )
            self.syn_packets[dst_ip] = []
            return alert
        return None

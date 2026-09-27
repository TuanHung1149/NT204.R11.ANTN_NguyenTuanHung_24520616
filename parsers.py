from scapy.all import IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw


def parse_tcp(packet):
    if not packet.haslayer(TCP):
        return None
    tcp = packet[TCP]
    return {
        "type": "TCP",
        "src_ip": packet[IP].src if packet.haslayer(IP) else None,
        "dst_ip": packet[IP].dst if packet.haslayer(IP) else None,
        "src_port": tcp.sport,
        "dst_port": tcp.dport,
        "flags": str(tcp.flags),
        "seq": tcp.seq,
        "ack": tcp.ack,
        "window": tcp.window,
    }


def parse_udp(packet):
    if not packet.haslayer(UDP):
        return None
    udp = packet[UDP]
    return {
        "type": "UDP",
        "src_ip": packet[IP].src if packet.haslayer(IP) else None,
        "dst_ip": packet[IP].dst if packet.haslayer(IP) else None,
        "src_port": udp.sport,
        "dst_port": udp.dport,
        "length": udp.len,
    }


def parse_dns(packet):
    if not packet.haslayer(DNS):
        return None

    dns = packet[DNS]
    result = {
        "type": "DNS",
        "src_ip": packet[IP].src if packet.haslayer(IP) else None,
        "dst_ip": packet[IP].dst if packet.haslayer(IP) else None,
        "is_query": dns.qr == 0,
        "queries": [],
        "answers": [],
    }

    # Trích xuất queries
    if dns.haslayer(DNSQR):
        qd = dns.qd
        while qd and hasattr(qd, "qname"):
            try:
                qname = qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                result["queries"].append({"name": qname, "type": qd.qtype})
                qd = qd.payload if qd.payload and isinstance(qd.payload, DNSQR) else None
            except AttributeError:
                break

    # Trích xuất answers
    if dns.haslayer(DNSRR):
        rr = dns.an
        while rr and hasattr(rr, "rrname"):
            try:
                rdata = rr.rdata
                if isinstance(rdata, bytes):
                    rdata = rdata.decode("utf-8", errors="ignore")
                result["answers"].append({
                    "name": rr.rrname.decode("utf-8", errors="ignore").rstrip("."),
                    "type": rr.type,
                    "data": str(rdata),
                })
                rr = rr.payload if rr.payload and isinstance(rr.payload, DNSRR) else None
            except AttributeError:
                break

    return result


def parse_http(packet):
    if not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return None

    tcp = packet[TCP]
    if tcp.dport not in (80, 8080) and tcp.sport not in (80, 8080):
        return None

    try:
        payload = packet[Raw].load.decode("utf-8", errors="ignore")
    except Exception:
        return None

    if not payload:
        return None

    result = {
        "type": "HTTP",
        "src_ip": packet[IP].src if packet.haslayer(IP) else None,
        "dst_ip": packet[IP].dst if packet.haslayer(IP) else None,
        "src_port": tcp.sport,
        "dst_port": tcp.dport,
    }

    lines = payload.split("\r\n")
    first_line = lines[0] if lines else ""

    http_methods = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")
    if any(first_line.startswith(m) for m in http_methods):
        parts = first_line.split(" ")
        result["direction"] = "request"
        result["method"] = parts[0] if len(parts) > 0 else ""
        result["path"] = parts[1] if len(parts) > 1 else ""
        result["version"] = parts[2] if len(parts) > 2 else ""
    elif first_line.startswith("HTTP/"):
        parts = first_line.split(" ", 2)
        result["direction"] = "response"
        result["version"] = parts[0] if len(parts) > 0 else ""
        result["status_code"] = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        result["status_text"] = parts[2] if len(parts) > 2 else ""
    else:
        return None

    headers = {}
    for line in lines[1:]:
        if not line:
            break
        if ": " in line:
            key, value = line.split(": ", 1)
            headers[key.lower()] = value
    result["headers"] = headers

    return result


def parse_packet(packet):
    for parser in [parse_http, parse_dns, parse_tcp, parse_udp]:
        result = parser(packet)
        if result:
            return result
    return None

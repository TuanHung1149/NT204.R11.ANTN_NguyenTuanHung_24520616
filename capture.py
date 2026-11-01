from scapy.all import sniff, IP, TCP, UDP, Raw, Padding


def start_capture(interface=None, packet_callback=None, count=0, timeout=None, bpf_filter=None):
    packets = sniff(
        iface=interface,
        prn=packet_callback,
        count=count,
        timeout=timeout,
        filter=bpf_filter,
        store=True,
    )
    return packets


def transport_payload(packet):
    # Lay toan bo du lieu sau header TCP/UDP (ke ca lop da duoc scapy phan tich
    # nhu DNS), bo phan padding cua khung Ethernet de dsize khong bi sai.
    for proto in (TCP, UDP):
        if not packet.haslayer(proto):
            continue
        payload = packet[proto].payload
        if not payload or isinstance(payload, Padding):
            return b""
        raw = bytes(payload)
        pad = payload.getlayer(Padding)
        if pad is not None:
            pad_len = len(bytes(pad))
            if pad_len:
                raw = raw[:-pad_len]
        return raw
    return b""


def extract_packet_info(packet):
    if not packet.haslayer(IP):
        return None

    # payload = dữ liệu ứng dụng, dùng cho content/dsize matching ở bài 3
    payload = transport_payload(packet)

    info = {
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": packet[IP].proto,
        "src_port": None,
        "dst_port": None,
        "size": len(packet),
        "payload": payload,
        "dsize": len(payload),
        "timestamp": float(packet.time),
    }

    if packet.haslayer(TCP):
        info["protocol"] = "TCP"
        info["src_port"] = packet[TCP].sport
        info["dst_port"] = packet[TCP].dport
        info["flags"] = str(packet[TCP].flags)
    elif packet.haslayer(UDP):
        info["protocol"] = "UDP"
        info["src_port"] = packet[UDP].sport
        info["dst_port"] = packet[UDP].dport

    return info

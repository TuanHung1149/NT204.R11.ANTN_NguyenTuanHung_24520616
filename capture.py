from scapy.all import sniff, IP, TCP, UDP


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


def extract_packet_info(packet):
    if not packet.haslayer(IP):
        return None

    info = {
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": packet[IP].proto,
        "src_port": None,
        "dst_port": None,
        "size": len(packet),
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

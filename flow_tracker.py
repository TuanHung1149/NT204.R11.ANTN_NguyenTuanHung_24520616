import time
import hashlib


def make_flow_id(src_ip, src_port, dst_ip, dst_port, protocol):
    # Sắp xếp 2 endpoint để A->B và B->A ra cùng 1 id
    a = (str(src_ip), src_port or 0)
    b = (str(dst_ip), dst_port or 0)
    low, high = sorted([a, b])
    key = f"{low[0]}:{low[1]}-{high[0]}:{high[1]}-{protocol}"
    return hashlib.md5(key.encode()).hexdigest()[:12]


class Flow:
    def __init__(self, event, now):
        self.flow_id = make_flow_id(
            event.get("src_ip"), event.get("src_port"),
            event.get("dst_ip"), event.get("dst_port"), event.get("protocol"),
        )
        self.protocol = event.get("protocol")
        self.application_protocol = event.get("type") if event.get("type") in ("HTTP", "DNS") else None

        # A = bên khởi tạo (gửi packet đầu tiên)
        self.endpoint_a = (event.get("src_ip"), event.get("src_port"))
        self.endpoint_b = (event.get("dst_ip"), event.get("dst_port"))

        self.start_time = now
        self.last_seen = now

        self.packet_count = 0
        self.byte_count = 0
        self.fwd_packets = 0
        self.fwd_bytes = 0
        self.bwd_packets = 0
        self.bwd_bytes = 0

        # Thống kê cờ TCP
        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.state = "NEW" if self.protocol == "tcp" else "ACTIVE"
        self._synack_seen = False

    def direction(self, event):
        src = (event.get("src_ip"), event.get("src_port"))
        return "forward" if src == self.endpoint_a else "backward"

    def update(self, event, now):
        self.last_seen = now
        size = event.get("size", 0)

        self.packet_count += 1
        self.byte_count += size

        if self.direction(event) == "forward":
            self.fwd_packets += 1
            self.fwd_bytes += size
        else:
            self.bwd_packets += 1
            self.bwd_bytes += size

        if self.protocol == "tcp":
            self._update_tcp_state(event.get("flags", ""))

    def _update_tcp_state(self, flags):
        has_syn = "S" in flags
        has_ack = "A" in flags
        has_fin = "F" in flags
        has_rst = "R" in flags

        if has_syn:
            self.syn_count += 1
        if has_ack:
            self.ack_count += 1
        if has_fin:
            self.fin_count += 1
        if has_rst:
            self.rst_count += 1

        if has_rst:
            self.state = "RESET"
            return

        if has_syn and has_ack:
            self._synack_seen = True
            self.state = "HANDSHAKE"
        elif has_syn:
            self.state = "HANDSHAKE"
        elif has_fin:
            self.state = "CLOSED" if self.state == "CLOSING" else "CLOSING"
        elif has_ack:
            if self.state == "HANDSHAKE" and self._synack_seen:
                self.state = "ESTABLISHED"

    def duration(self):
        return round(self.last_seen - self.start_time, 6)

    def to_dict(self):
        return {
            "flow_id": self.flow_id,
            "protocol": self.protocol,
            "application_protocol": self.application_protocol,
            "endpoint_a": f"{self.endpoint_a[0]}:{self.endpoint_a[1]}",
            "endpoint_b": f"{self.endpoint_b[0]}:{self.endpoint_b[1]}",
            "start_time": self.start_time,
            "last_seen": self.last_seen,
            "duration": self.duration(),
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "forward": {"packets": self.fwd_packets, "bytes": self.fwd_bytes},
            "backward": {"packets": self.bwd_packets, "bytes": self.bwd_bytes},
            "state": self.state,
            "tcp_flags": {
                "SYN": self.syn_count, "ACK": self.ack_count,
                "FIN": self.fin_count, "RST": self.rst_count,
            },
        }


class FlowTracker:
    def __init__(self, tcp_timeout=300, udp_timeout=60):
        self.tcp_timeout = tcp_timeout
        self.udp_timeout = udp_timeout
        self.flows = {}        # flow_id -> Flow
        self.closed_flows = []

    def process(self, event, now=None):
        if now is None:
            now = time.time()

        flow_id = make_flow_id(
            event.get("src_ip"), event.get("src_port"),
            event.get("dst_ip"), event.get("dst_port"), event.get("protocol"),
        )

        if flow_id not in self.flows:
            self.flows[flow_id] = Flow(event, now)

        flow = self.flows[flow_id]
        flow.update(event, now)

        # Flow TCP đóng thì chuyển sang danh sách closed
        if flow.state in ("CLOSED", "RESET"):
            self.closed_flows.append(flow)
            del self.flows[flow_id]

        return flow

    def expire_flows(self, now=None):
        # Đóng các flow quá hạn idle timeout, loại khỏi active table
        if now is None:
            now = time.time()

        expired = []
        for flow_id in list(self.flows.keys()):
            flow = self.flows[flow_id]
            timeout = self.tcp_timeout if flow.protocol == "tcp" else self.udp_timeout
            if now - flow.last_seen > timeout:
                flow.state = "CLOSED"
                expired.append(flow)
                self.closed_flows.append(flow)
                del self.flows[flow_id]
        return expired

    def active_flows(self):
        return list(self.flows.values())

    def all_flows(self):
        return list(self.flows.values()) + self.closed_flows

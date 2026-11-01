import os
from scapy.all import rdpcap
from capture import extract_packet_info
from parsers import parse_packet
from decoder import decode_event
from preprocessor import preprocess
from flow_tracker import FlowTracker
from evaluation_engine import build_engine

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
APP_PROTOCOLS = ("HTTP", "DNS", "SMTP")


class IDSPipeline:
    # Gom ca day chuyen: Capture -> Parser -> Decoder -> Preprocessor
    # -> Flow Tracker -> Core Engine. Khong in gi, chi tra du lieu.

    def __init__(self, config_path=None, base_dir=None):
        base_dir = base_dir or BASE_DIR
        config_path = config_path or os.path.join(base_dir, "config", "engine.json")
        self.engine = build_engine(config_path, base_dir)
        self.flow_tracker = FlowTracker()
        self.packet_count = 0
        self.skipped = []
        self.detections = []

    def build_event(self, packet):
        info = extract_packet_info(packet)
        if not info:
            return None

        event = dict(info)
        parsed = parse_packet(packet)
        if parsed and parsed.get("type"):
            event["type"] = parsed["type"]
            if "path" in parsed:
                event["path"] = parsed["path"]
            if "headers" in parsed:
                event["headers"] = parsed["headers"]
            if parsed["type"] == "DNS":
                event["app_data"] = " ".join(q["name"] for q in parsed.get("queries", []))

        event = decode_event(event)
        if event.get("decoded_path"):
            event["app_data"] = event["decoded_path"]
        return preprocess(event)

    def flow_context(self, event, flow):
        return {
            "flow_id": flow.flow_id,
            "state": flow.state,
            "to_server": flow.direction(event) == "forward",
            "established": flow.state in ("ESTABLISHED", "CLOSING"),
            "application_protocol": flow.application_protocol,
        }

    def process(self, packet):
        # Tra ve danh sach detection event cua rieng goi nay
        self.packet_count += 1
        try:
            event = self.build_event(packet)
            if event is None:
                self.skipped.append((self.packet_count, "khong phai goi IP"))
                return []
            if event.get("processing_action") == "drop":
                self.skipped.append((self.packet_count, "preprocessor loai bo"))
                return []

            flow = self.flow_tracker.process(event, now=event.get("timestamp"))
            found = self.engine.evaluate(event, self.flow_context(event, flow))
            self.detections.extend(found)
            return found
        except Exception as e:
            self.skipped.append((self.packet_count, f"{type(e).__name__}: {e}"))
            return []

    def process_pcap(self, path):
        for packet in rdpcap(path):
            self.process(packet)
        return self.detections

    def detections_by_sid(self, sid):
        return [d for d in self.detections if d["sid"] == sid]

    def report(self):
        return dict(self.engine.report(), packets=self.packet_count,
                    skipped=len(self.skipped), detections=len(self.detections))

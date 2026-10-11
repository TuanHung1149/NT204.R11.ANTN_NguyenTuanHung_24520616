import ipaddress

REQUIRED_FIELDS = ["src_ip", "dst_ip", "protocol"]
VALID_PROTOCOLS = {"tcp", "udp", "dns", "http", "icmp"}


def _valid_port(port):
    return port is None or (isinstance(port, int) and 0 <= port <= 65535)


def _valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except (ValueError, TypeError):
        return False


def validate(event):
    # Trả về trạng thái: valid / partial / invalid + lý do
    reasons = []

    for field in REQUIRED_FIELDS:
        if not event.get(field):
            reasons.append(f"missing {field}")

    if not _valid_port(event.get("src_port")):
        reasons.append("bad src_port")
    if not _valid_port(event.get("dst_port")):
        reasons.append("bad dst_port")

    if event.get("src_ip") and not _valid_ip(event["src_ip"]):
        reasons.append("bad src_ip")
    if event.get("dst_ip") and not _valid_ip(event["dst_ip"]):
        reasons.append("bad dst_ip")

    proto = str(event.get("protocol", "")).lower()
    if proto and proto not in VALID_PROTOCOLS:
        reasons.append("unknown protocol")

    missing_required = any(r.startswith("missing") for r in reasons)
    if missing_required:
        return "invalid", reasons
    if reasons:
        return "partial", reasons
    return "valid", reasons


def normalize(event):
    # Chuẩn hóa: protocol/IP/domain về chữ thường, header name chữ thường
    result = dict(event)

    if "protocol" in result and isinstance(result["protocol"], str):
        result["protocol"] = result["protocol"].lower()

    for key in ("src_ip", "dst_ip"):
        if result.get(key) and isinstance(result[key], str):
            result[key] = result[key].strip().lower()

    headers = result.get("headers")
    if isinstance(headers, dict):
        result["headers"] = {k.lower(): v for k, v in headers.items()}
        if "host" in result["headers"]:
            result["headers"]["host"] = result["headers"]["host"].strip().lower()

    if result.get("path") and isinstance(result["path"], str):
        result["path"] = result["path"].strip()

    return result


def fill_missing(event):
    # Field thiếu dùng giá trị nhất quán: None cho scalar, [] cho list
    result = dict(event)
    defaults = {
        "src_port": None,
        "dst_port": None,
        "src_ip": None,
        "dst_ip": None,
        "protocol": None,
    }
    for key, value in defaults.items():
        result.setdefault(key, value)
    if "headers" in result and result["headers"] is None:
        result["headers"] = {}
    return result


def preprocess(event):
    # Gộp 3 bước: fill missing -> normalize -> validate, thêm metadata
    if not isinstance(event, dict):
        return {
            "preprocess_status": "invalid",
            "processing_action": "drop",
            "reason": ["event is not a dict"],
        }

    result = fill_missing(event)
    result = normalize(result)
    status, reasons = validate(result)

    result["preprocess_status"] = status
    result["processing_action"] = "drop" if status == "invalid" else "keep"
    result["reason"] = reasons
    return result

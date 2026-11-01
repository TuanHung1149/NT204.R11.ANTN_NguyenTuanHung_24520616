import ipaddress

FLAG_MODIFIERS = "+*!"


def _ip_matches(ip_text, spec):
    if spec["any"]:
        result = True
    else:
        try:
            ip = ipaddress.ip_address(str(ip_text))
        except ValueError:
            return False
        result = any(ip in net for net in spec["nets"])
    return (not result) if spec["negate"] else result


def _port_matches(port, spec):
    if port is None:
        result = spec["any"]
    elif spec["any"]:
        result = True
    else:
        result = any(lo <= port <= hi for lo, hi in spec["ranges"])
    return (not result) if spec["negate"] else result


def _one_way(header, src_ip, src_port, dst_ip, dst_port):
    return (_ip_matches(src_ip, header["src_ip"])
            and _port_matches(src_port, header["src_port"])
            and _ip_matches(dst_ip, header["dst_ip"])
            and _port_matches(dst_port, header["dst_port"]))


def match_header(rule, event):
    header = rule["header"]
    proto = str(event.get("protocol", "")).lower()

    if header["protocol"] != "ip" and header["protocol"] != proto:
        return False, f"protocol {proto} != {header['protocol']}"

    src_ip, dst_ip = event.get("src_ip"), event.get("dst_ip")
    src_port, dst_port = event.get("src_port"), event.get("dst_port")

    if _one_way(header, src_ip, src_port, dst_ip, dst_port):
        return True, None
    # Huong <> kiem tra them chieu nguoc lai
    if header["direction"] == "<>" and _one_way(header, dst_ip, dst_port, src_ip, src_port):
        return True, None
    return False, "khong khop IP/port/huong"


def match_flow(rule, flow_ctx):
    want = rule.get("flow") or {}
    if not want:
        return True, None
    if flow_ctx is None:
        return False, "rule can flow context nhung event khong co"

    if "direction" in want:
        to_server = bool(flow_ctx.get("to_server"))
        if want["direction"] == "to_server" and not to_server:
            return False, "khong phai to_server"
        if want["direction"] == "to_client" and to_server:
            return False, "khong phai to_client"

    if "state" in want:
        established = bool(flow_ctx.get("established"))
        if want["state"] == "established" and not established:
            return False, "flow chua established"
        if want["state"] == "not_established" and established:
            return False, "flow da established"
    return True, None


def match_flags(rule, event):
    spec = rule.get("flags")
    if not spec:
        return True, None

    modifier = spec[0] if spec[0] in FLAG_MODIFIERS else ""
    want = set(spec[len(modifier):].upper()) - {"0"}
    have = set(str(event.get("flags", "")).upper())

    if modifier == "+":
        ok = want <= have
    elif modifier == "*":
        ok = bool(want & have)
    elif modifier == "!":
        ok = not (want & have)
    else:
        ok = want == have
    return (True, None) if ok else (False, f"flags {''.join(sorted(have)) or '-'} != {spec}")


def match_dsize(rule, event):
    spec = rule.get("dsize")
    if not spec:
        return True, None

    dsize = int(event.get("dsize") or 0)
    try:
        if "<>" in spec:
            lo, hi = spec.split("<>", 1)
            ok = int(lo) <= dsize <= int(hi)      # hai dau inclusive
        elif spec.startswith(">="):
            ok = dsize >= int(spec[2:])
        elif spec.startswith("<="):
            ok = dsize <= int(spec[2:])
        elif spec.startswith(">"):
            ok = dsize > int(spec[1:])
        elif spec.startswith("<"):
            ok = dsize < int(spec[1:])
        else:
            ok = dsize == int(spec)
    except ValueError:
        return False, f"dsize spec khong hop le: {spec}"
    return (True, None) if ok else (False, f"dsize {dsize} khong thoa {spec}")


def _find(payload, pattern, nocase, start, end):
    if start >= end:
        return -1
    hay = payload[start:end]
    needle = pattern
    if nocase:
        hay, needle = hay.lower(), needle.lower()
    pos = hay.find(needle)
    return start + pos if pos >= 0 else -1


def _window(content, payload, prev_end):
    if content["distance"] is not None or content["within"] is not None:
        base = prev_end + (content["distance"] or 0)
        start = base
        end = base + content["within"] if content["within"] is not None else len(payload)
    else:
        start = content["offset"] or 0
        end = start + content["depth"] if content["depth"] is not None else len(payload)
    return max(0, start), min(len(payload), end)


def _match_contents(contents, i, payload, prev_end, found):
    # Quay lui: neu content sau that bai thi thu vi tri ke tiep cua content truoc
    if i >= len(contents):
        return True

    content = contents[i]
    start, end = _window(content, payload, prev_end)
    search_from = start

    while True:
        pos = _find(payload, content["pattern"], content["nocase"], search_from, end)
        if pos < 0:
            return False
        hit_end = pos + len(content["pattern"])
        found.append({
            "content": content["raw"],
            "offset": pos,
            "matched": payload[pos:hit_end].decode("utf-8", errors="replace"),
            "nocase": content["nocase"],
        })
        if _match_contents(contents, i + 1, payload, hit_end, found):
            return True
        found.pop()
        search_from = pos + 1


def _as_bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", errors="replace")
    return b""


def match_content(rule, event):
    contents = rule.get("contents") or []
    if not contents:
        return True, None, []

    # Tim trong payload tho; neu khong co thi tim trong du lieu ung dung da
    # parse/decode (DNS qname, URI da giai ma) theo muc 4.4 cua de bai.
    buffers = [("payload", _as_bytes(event.get("payload"))),
               ("app_data", _as_bytes(event.get("app_data")))]

    for name, buf in buffers:
        if not buf:
            continue
        found = []
        if _match_contents(contents, 0, buf, 0, found):
            for item in found:
                item["field"] = name
            return True, None, found
    return False, "khong tim thay content trong payload/app_data", []


def match_rule(rule, event, flow_ctx=None):
    # Thu tu kiem tra: header -> flow -> flags/dsize -> content
    for stage, check in (
        ("header", lambda: match_header(rule, event)),
        ("flow", lambda: match_flow(rule, flow_ctx)),
        ("flags", lambda: match_flags(rule, event)),
        ("dsize", lambda: match_dsize(rule, event)),
    ):
        ok, reason = check()
        if not ok:
            return {"match": False, "stage": stage, "reason": reason,
                    "sid": rule.get("sid"), "matched": []}

    ok, reason, found = match_content(rule, event)
    if not ok:
        return {"match": False, "stage": "content", "reason": reason,
                "sid": rule.get("sid"), "matched": []}

    return {"match": True, "stage": None, "reason": None,
            "sid": rule.get("sid"), "matched": found}

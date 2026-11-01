from datetime import datetime


def _timestamp(event):
    ts = event.get("timestamp")
    if ts is None:
        return datetime.now().isoformat()
    try:
        return datetime.fromtimestamp(float(ts)).isoformat()
    except (ValueError, OSError, OverflowError):
        return str(ts)


def create_detection_event(rule, event, match_result, flow_ctx=None):
    flow_ctx = flow_ctx or {}
    return {
        "timestamp": _timestamp(event),
        "sid": rule.get("sid"),
        "rev": rule.get("rev"),
        "msg": rule.get("msg"),
        "classtype": rule.get("classtype"),
        "priority": rule.get("priority"),
        "protocol": str(event.get("protocol", "")).lower(),
        "application_protocol": event.get("type") or flow_ctx.get("application_protocol"),
        "src_ip": event.get("src_ip"),
        "src_port": event.get("src_port"),
        "dst_ip": event.get("dst_ip"),
        "dst_port": event.get("dst_port"),
        "flow_id": flow_ctx.get("flow_id"),
        "flow_state": flow_ctx.get("state"),
        "match_info": match_result.get("matched", []),
    }


def format_detection_event(de):
    src = f"{de['src_ip']}:{de['src_port']}" if de["src_port"] else de["src_ip"]
    dst = f"{de['dst_ip']}:{de['dst_port']}" if de["dst_port"] else de["dst_ip"]
    head = (f"[{de['sid']}:{de['rev']}] {de['msg']} "
            f"[priority:{de['priority']}] [{de['classtype']}]")
    line = f"  {de['protocol'].upper()} {src} -> {dst}"
    if de["application_protocol"]:
        line += f" | app={de['application_protocol']}"
    if de["flow_id"]:
        line += f" | flow={de['flow_id']} ({de['flow_state']})"
    parts = [head, line]
    for m in de["match_info"]:
        parts.append(f'  matched content="{m["content"]}" @offset={m["offset"]}')
    return "\n".join(parts)

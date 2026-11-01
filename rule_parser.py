import ipaddress

SUPPORTED_ACTIONS = {"alert"}
SUPPORTED_PROTOCOLS = {"tcp", "udp", "ip"}
SUPPORTED_DIRECTIONS = {"->", "<>"}

# Keyword xu ly duoc
CONTENT_MODIFIERS = {"nocase", "offset", "depth", "distance", "within"}
SUPPORTED_KEYWORDS = {
    "msg", "sid", "rev", "content", "flags", "dsize",
    "flow", "classtype", "priority",
} | CONTENT_MODIFIERS

# Keyword chap nhan nhung bo qua (khong anh huong detection)
IGNORED_KEYWORDS = {"reference", "metadata", "gid", "fast_pattern", "sid_rev"}

FLOW_VALUES = {
    "to_server": ("direction", "to_server"),
    "from_client": ("direction", "to_server"),
    "to_client": ("direction", "to_client"),
    "from_server": ("direction", "to_client"),
    "established": ("state", "established"),
    "not_established": ("state", "not_established"),
}

VALID_FLAG_CHARS = set("FSRPAUCE0")
FLAG_MODIFIERS = set("+*!")


class RuleError(Exception):
    pass


class RuleUnsupported(Exception):
    pass


def split_options(text):
    # Tach option theo ';' nhung bo qua ';' nam trong dau nhay hoac bi escape
    parts, buf = [], []
    in_quote = False
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text):
            buf.append(c)
            buf.append(text[i + 1])
            i += 2
            continue
        if c == '"':
            in_quote = not in_quote
            buf.append(c)
        elif c == ";" and not in_quote:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(c)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return [p for p in parts if p]


def parse_content_pattern(raw):
    # Chuyen text content thanh bytes: ho tro escape \" \\ \; \| va khoi hex |2E 2E|
    out = bytearray()
    i = 0
    while i < len(raw):
        c = raw[i]
        if c == "\\" and i + 1 < len(raw):
            out.extend(raw[i + 1].encode("utf-8"))
            i += 2
        elif c == "|":
            end = raw.find("|", i + 1)
            if end == -1:
                raise RuleError("khoi hex thieu dau | dong")
            for token in raw[i + 1:end].split():
                try:
                    out.append(int(token, 16))
                except ValueError:
                    raise RuleError(f"byte hex khong hop le: {token}")
            i = end + 1
        else:
            out.extend(c.encode("utf-8"))
            i += 1
    return bytes(out)


def parse_ip_spec(spec):
    spec = spec.strip()
    if spec.startswith("$"):
        raise RuleError(f"bien chua dinh nghia trong config: {spec}")
    negate = spec.startswith("!")
    if negate:
        spec = spec[1:].strip()

    if spec.lower() == "any":
        return {"any": True, "negate": negate, "nets": []}

    items = spec[1:-1].split(",") if spec.startswith("[") and spec.endswith("]") else [spec]
    nets = []
    for item in items:
        item = item.strip()
        if not item:
            continue
        if item.lower() == "any":
            return {"any": True, "negate": negate, "nets": []}
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            raise RuleError(f"IP/CIDR khong hop le: {item}")
    if not nets:
        raise RuleError(f"IP rong: {spec}")
    return {"any": False, "negate": negate, "nets": nets}


def parse_port_spec(spec):
    spec = spec.strip()
    if spec.startswith("$"):
        raise RuleError(f"bien chua dinh nghia trong config: {spec}")
    negate = spec.startswith("!")
    if negate:
        spec = spec[1:].strip()

    if spec.lower() == "any":
        return {"any": True, "negate": negate, "ranges": []}

    items = spec[1:-1].split(",") if spec.startswith("[") and spec.endswith("]") else [spec]
    ranges = []
    for item in items:
        item = item.strip()
        if not item:
            continue
        if item.lower() == "any":
            return {"any": True, "negate": negate, "ranges": []}
        try:
            if ":" in item:
                lo, hi = item.split(":", 1)
                lo = int(lo) if lo.strip() else 0
                hi = int(hi) if hi.strip() else 65535
            else:
                lo = hi = int(item)
        except ValueError:
            raise RuleError(f"port khong hop le: {item}")
        if not (0 <= lo <= 65535 and 0 <= hi <= 65535) or lo > hi:
            raise RuleError(f"port ngoai pham vi: {item}")
        ranges.append((lo, hi))
    if not ranges:
        raise RuleError(f"port rong: {spec}")
    return {"any": False, "negate": negate, "ranges": ranges}


def parse_header(text):
    tokens = text.split()
    if len(tokens) != 7:
        raise RuleError(f"header phai co 7 phan, dang co {len(tokens)}")

    action, proto, src_ip, src_port, direction, dst_ip, dst_port = tokens

    if action.lower() not in SUPPORTED_ACTIONS:
        raise RuleUnsupported(f"action '{action}' khong ho tro")
    if proto.lower() not in SUPPORTED_PROTOCOLS:
        raise RuleUnsupported(f"protocol '{proto}' khong ho tro")
    if direction not in SUPPORTED_DIRECTIONS:
        raise RuleError(f"direction '{direction}' khong hop le")

    return {
        "action": action.lower(),
        "protocol": proto.lower(),
        "direction": direction,
        "src_ip": parse_ip_spec(src_ip),
        "src_port": parse_port_spec(src_port),
        "dst_ip": parse_ip_spec(dst_ip),
        "dst_port": parse_port_spec(dst_port),
    }


def _strip_quotes(value):
    value = value.strip()
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value


def _content_value(value):
    # Phai dung dang "..." ; '!' (phu dinh) va tham so kieu Snort3 ("x",nocase)
    # deu chua ho tro -> bao unsupported thay vi hieu nham thanh chuoi literal.
    v = (value or "").strip()
    if v.startswith("!"):
        raise RuleUnsupported("content phu dinh '!' chua ho tro")
    if not v.startswith('"'):
        raise RuleError(f"content phai dat trong dau nhay: {value}")

    i = 1
    closing = -1
    while i < len(v):
        if v[i] == "\\" and i + 1 < len(v):
            i += 2
            continue
        if v[i] == '"':
            closing = i
            break
        i += 1
    if closing == -1:
        raise RuleError(f"content thieu dau nhay dong: {value}")
    if closing != len(v) - 1:
        raise RuleUnsupported(f"content co tham so phu chua ho tro: {v[closing + 1:]}")
    return v[1:closing]


def _int_option(name, value):
    try:
        return int(_strip_quotes(value))
    except (ValueError, TypeError):
        raise RuleError(f"{name} phai la so nguyen, nhan '{value}'")


def parse_options(text):
    rule = {
        "msg": None, "sid": None, "rev": None,
        "contents": [], "flow": {}, "flags": None, "dsize": None,
        "classtype": None, "priority": None,
    }

    for option in split_options(text):
        if ":" in option:
            name, value = option.split(":", 1)
            name, value = name.strip().lower(), value.strip()
        else:
            name, value = option.strip().lower(), None

        if name in IGNORED_KEYWORDS:
            continue
        if name not in SUPPORTED_KEYWORDS:
            raise RuleUnsupported(f"keyword '{name}' ngoai pham vi")

        if name == "msg":
            rule["msg"] = _strip_quotes(value)
        elif name == "sid":
            rule["sid"] = _int_option("sid", value)
        elif name == "rev":
            rule["rev"] = _int_option("rev", value)
        elif name == "priority":
            rule["priority"] = _int_option("priority", value)
        elif name == "classtype":
            rule["classtype"] = _strip_quotes(value)
        elif name == "content":
            if value is None:
                raise RuleError("content thieu gia tri")
            text = _content_value(value)
            rule["contents"].append({
                "pattern": parse_content_pattern(text),
                "raw": text,
                "nocase": False, "offset": None, "depth": None,
                "distance": None, "within": None,
            })
        elif name in CONTENT_MODIFIERS:
            # Modifier phai gan vao content dung ngay truoc no
            if not rule["contents"]:
                raise RuleError(f"'{name}' khong co content dung truoc")
            last = rule["contents"][-1]
            if name == "nocase":
                last["nocase"] = True
            else:
                last[name] = _int_option(name, value)
        elif name == "flags":
            if not value:
                raise RuleError("flags thieu gia tri")
            spec = value.split(",")[0].strip()
            body = spec.lstrip("".join(FLAG_MODIFIERS)).upper()
            if not body or any(ch not in VALID_FLAG_CHARS for ch in body):
                raise RuleError(f"flags khong hop le: {value}")
            rule["flags"] = spec
        elif name == "dsize":
            if not value:
                raise RuleError("dsize thieu gia tri")
            rule["dsize"] = value.strip()
        elif name == "flow":
            for part in (value or "").split(","):
                part = part.strip().lower()
                if not part:
                    continue
                if part not in FLOW_VALUES:
                    raise RuleUnsupported(f"flow '{part}' ngoai pham vi")
                key, val = FLOW_VALUES[part]
                rule["flow"][key] = val

    if rule["sid"] is None:
        raise RuleError("thieu sid")
    return rule


def parse_rule(text, source=None, lineno=None):
    # Tra ve Internal Rule Object kem status: valid / invalid / unsupported
    rule = {"raw": text, "file": source, "lineno": lineno,
            "status": "valid", "reason": None}
    try:
        start = text.find("(")
        end = text.rfind(")")
        if start == -1 or end == -1 or end < start:
            raise RuleError("thieu dau ngoac cho phan options")

        rule["header"] = parse_header(text[:start])
        rule.update(parse_options(text[start + 1:end]))
    except RuleUnsupported as e:
        rule["status"] = "unsupported"
        rule["reason"] = str(e)
    except RuleError as e:
        rule["status"] = "invalid"
        rule["reason"] = str(e)
    except Exception as e:
        rule["status"] = "invalid"
        rule["reason"] = f"loi parse: {e}"
    return rule


def parse_rules(lines):
    return [parse_rule(l["text"], l["file"], l["lineno"]) for l in lines]

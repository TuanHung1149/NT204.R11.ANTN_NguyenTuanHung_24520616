from collections import defaultdict

ANY_PORT = "*"
MAX_INDEXED_PORTS = 8


def _single_ports(spec):
    # Tra ve danh sach port don le neu index duoc, nguoc lai None (dung bucket "*")
    if spec["any"] or spec["negate"]:
        return None
    ports = []
    for lo, hi in spec["ranges"]:
        if lo != hi:
            return None
        ports.append(lo)
    if not ports or len(ports) > MAX_INDEXED_PORTS:
        return None
    return ports


class RuleRepository:
    def __init__(self):
        self.rules = []
        self.invalid = []
        self.unsupported = []
        self.index = defaultdict(list)

    def add(self, rule):
        status = rule.get("status")
        if status == "invalid":
            self.invalid.append(rule)
        elif status == "unsupported":
            self.unsupported.append(rule)
        else:
            rule["_idx"] = len(self.rules)
            self.rules.append(rule)
            self._index_rule(rule)

    def add_many(self, rules):
        for rule in rules:
            self.add(rule)

    def _index_rule(self, rule):
        proto = rule["header"]["protocol"]
        # Neu mot ben port index duoc thi moi event khop deu phai co port do o
        # mot trong hai dau -> chi can index theo cac port do (ke ca huong <>).
        ports = set()
        for name in ("src_port", "dst_port"):
            single = _single_ports(rule["header"][name])
            if single:
                ports.update(single)

        keys = {(proto, p) for p in ports} if ports else {(proto, ANY_PORT)}
        for key in keys:
            self.index[key].append(rule)

    def candidates(self, event):
        proto = str(event.get("protocol", "")).lower()
        ports = [event.get("src_port"), event.get("dst_port"), ANY_PORT]

        found = {}
        # rule khai bao 'ip' ap dung cho ca tcp lan udp
        for p in (proto, "ip"):
            for port in ports:
                if port is None:
                    continue
                for rule in self.index.get((p, port), []):
                    found[rule["_idx"]] = rule

        return [found[i] for i in sorted(found)]

    def stats(self):
        return {
            "valid": len(self.rules),
            "invalid": len(self.invalid),
            "unsupported": len(self.unsupported),
            "index_buckets": len(self.index),
        }


def build_repository(rules):
    repo = RuleRepository()
    repo.add_many(rules)
    return repo

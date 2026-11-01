import os
import re
import json

SID_RE = re.compile(r"\bsid\s*:\s*(\d+)")


def load_config(path):
    with open(path) as f:
        return json.load(f)


def expand_variables(text, variables):
    # $HOME_NET -> 10.0.0.0/8 ; thay bien dai truoc de tranh $HTTP_PORTS bi cat
    for name in sorted(variables, key=len, reverse=True):
        text = text.replace("$" + name, str(variables[name]))
    return text


def read_rule_file(path, variables=None):
    # Tra ve danh sach dong rule (bo comment/dong trong) + canh bao
    lines, warnings = [], []
    if not os.path.isfile(path):
        warnings.append(f"{path}: file khong ton tai")
        return lines, warnings

    with open(path, encoding="utf-8", errors="replace") as f:
        for lineno, raw in enumerate(f, start=1):
            text = raw.strip()
            if not text or text.startswith("#"):
                continue
            if variables:
                text = expand_variables(text, variables)
            lines.append({"file": path, "lineno": lineno, "text": text})
    return lines, warnings


def load_rules(config, base_dir="."):
    # Doc tat ca rule file duoc bat trong config, bo cac sid bi disable
    variables = config.get("variables", {})
    disabled = set(config.get("disabled_sids", []))

    all_lines, all_warnings = [], []
    for entry in config.get("rule_files", []):
        if not entry.get("enabled", True):
            all_warnings.append(f"{entry.get('path')}: bi tat trong config")
            continue

        path = os.path.join(base_dir, entry["path"])
        lines, warnings = read_rule_file(path, variables)
        all_warnings.extend(warnings)

        for line in lines:
            m = SID_RE.search(line["text"])
            if m and int(m.group(1)) in disabled:
                all_warnings.append(f"sid {m.group(1)}: bi tat trong config")
                continue
            all_lines.append(line)

    return all_lines, all_warnings

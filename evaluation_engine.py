from rule_loader import load_config, load_rules
from rule_parser import parse_rules
from rule_repository import build_repository
from rule_matcher import match_rule
from detection_event import create_detection_event


class EvaluationEngine:
    def __init__(self, repository, warnings=None):
        self.repository = repository
        self.warnings = warnings or []
        self.stats = {"events": 0, "candidates": 0, "matches": 0, "rules_skipped": 0}

    def evaluate(self, event, flow_ctx=None):
        # Lay candidate tu indexer roi thu tung rule, khong dung o match dau tien
        self.stats["events"] += 1
        candidates = self.repository.candidates(event)
        self.stats["candidates"] += len(candidates)
        self.stats["rules_skipped"] += len(self.repository.rules) - len(candidates)

        detections = []
        for rule in candidates:
            result = match_rule(rule, event, flow_ctx)
            if result["match"]:
                self.stats["matches"] += 1
                detections.append(create_detection_event(rule, event, result, flow_ctx))
        return detections

    def report(self):
        return dict(self.stats, **self.repository.stats())


def build_engine(config_path="config/engine.json", base_dir="."):
    config = load_config(config_path)
    lines, warnings = load_rules(config, base_dir)
    rules = parse_rules(lines)
    repo = build_repository(rules)

    for rule in repo.invalid:
        warnings.append(f"{rule['file']}:{rule['lineno']} invalid - {rule['reason']}")
    for rule in repo.unsupported:
        warnings.append(f"{rule['file']}:{rule['lineno']} unsupported - {rule['reason']}")

    return EvaluationEngine(repo, warnings)

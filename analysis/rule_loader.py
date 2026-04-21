from typing import Any, Dict, List
import yaml


def load_rules(path: str = "analysis/rules/detection_rules.yaml") -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    rules = data.get("rules", [])
    enabled_rules = [rule for rule in rules if rule.get("enabled", True)]
    return enabled_rules


def split_rules_by_type(rules: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    result = {
        "single_event": [],
        "aggregation": [],
    }

    for rule in rules:
        rule_type = rule.get("type")
        if rule_type in result:
            result[rule_type].append(rule)

    return result
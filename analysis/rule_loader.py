import os
from typing import List, Dict, Any

import yaml


RULES_PATH = os.getenv(
    "DETECTION_RULES_PATH",
    os.path.join(os.path.dirname(__file__), "rules", "detection_rules.yaml"),
)


def load_rules() -> List[Dict[str, Any]]:
    if not os.path.exists(RULES_PATH):
        raise FileNotFoundError(f"Detection rules file not found: {RULES_PATH}")

    with open(RULES_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    rules = data.get("rules", [])
    if not isinstance(rules, list):
        raise ValueError("Invalid rules format: 'rules' must be a list")

    enabled_rules = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if rule.get("enabled", True):
            enabled_rules.append(rule)

    return enabled_rules
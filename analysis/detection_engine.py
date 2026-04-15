from typing import Any, Dict, List

from analysis.rule_loader import load_rules
from analysis.evaluators.single_event import evaluate_single_event_rule
from analysis.evaluators.aggregation import evaluate_aggregation_rule


def _empty_detection() -> Dict[str, Any]:
    return {
        "detected": False,
        "rule_id": None,
        "rule_name": None,
        "reason": [],
        "attack_tactic": None,
        "attack_technique": None,
        "response_guide": [],
    }


def _empty_risk() -> Dict[str, Any]:
    return {
        "base_score": 0,
        "weight": 0,
        "final_score": 0,
        "severity": "none",
    }


def evaluate_detection(event_dict: Dict[str, Any], normalized: Dict[str, Any]):
    rules = load_rules()
    matched_results: List[Dict[str, Any]] = []

    for rule in rules:
        rule_type = rule.get("type")

        if rule_type == "single_event":
            result = evaluate_single_event_rule(rule, event_dict, normalized)

        elif rule_type == "aggregation":
            result = evaluate_aggregation_rule(rule, event_dict, normalized)

        else:
            result = None

        if result:
            matched_results.append(result)

    if not matched_results:
        return _empty_detection(), _empty_risk()

    # 점수가 가장 높은 룰 하나 선택
    best = max(
        matched_results,
        key=lambda x: x.get("risk", {}).get("final_score", 0)
    )

    detection = {
        "detected": True,
        "rule_id": best.get("rule_id"),
        "rule_name": best.get("rule_name"),
        "reason": best.get("reason", []),
        "attack_tactic": best.get("attack_tactic"),
        "attack_technique": best.get("attack_technique"),
        "response_guide": best.get("response_guide", []),
    }

    risk = best.get("risk", _empty_risk())

    return detection, risk
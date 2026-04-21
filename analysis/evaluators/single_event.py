from typing import Any, Dict, Optional


def _get_field_value(field: str, event_dict: Dict[str, Any], normalized: Dict[str, Any]) -> Any:
    if field in normalized:
        return normalized.get(field)
    return event_dict.get(field)


def _match_conditions(match: Dict[str, Any], event_dict: Dict[str, Any], normalized: Dict[str, Any]) -> bool:
    for field, expected in match.items():
        actual = _get_field_value(field, event_dict, normalized)
        if actual != expected:
            return False
    return True


def evaluate_single_event_rule(
    rule: Dict[str, Any],
    event_dict: Dict[str, Any],
    normalized: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    match = rule.get("match", {})
    if not _match_conditions(match, event_dict, normalized):
        return None

    base_score = int(rule.get("score", 0))
    severity = rule.get("severity", "low")

    return {
        "detected": True,
        "rule_id": rule.get("rule_id"),
        "rule_name": rule.get("name"),
        "reason": [f"{rule.get('name')} 조건과 일치하는 이벤트입니다."],
        "attack_tactic": rule.get("attack", {}).get("tactic"),
        "attack_technique": rule.get("attack", {}).get("technique"),
        "response_guide": rule.get("response_guide", []),
        "risk": {
            "base_score": base_score,
            "weight": 1,
            "final_score": base_score,
            "severity": severity,
        },
    }
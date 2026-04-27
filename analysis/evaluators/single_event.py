from typing import Any, Dict, Optional


def _get_field_value(field: str, event_dict: Dict[str, Any], normalized: Dict[str, Any]) -> Any:
    if field in normalized:
        return normalized.get(field)
    return event_dict.get(field)


def _match_exact(match: Dict[str, Any], event_dict: Dict[str, Any], normalized: Dict[str, Any]) -> bool:
    for field, expected in match.items():
        actual = _get_field_value(field, event_dict, normalized)
        if actual != expected:
            return False
    return True


def _match_any(match_any: Dict[str, Any], event_dict: Dict[str, Any], normalized: Dict[str, Any]) -> bool:
    for field, candidates in match_any.items():
        actual = _get_field_value(field, event_dict, normalized)

        if actual is None:
            return False

        actual_str = str(actual).lower()
        normalized_candidates = [str(x).lower() for x in candidates]

        if actual_str not in normalized_candidates:
            return False

    return True


def _contains_any(contains_any: Dict[str, Any], event_dict: Dict[str, Any], normalized: Dict[str, Any]) -> bool:
    for field, keywords in contains_any.items():
        actual = _get_field_value(field, event_dict, normalized)

        if actual is None:
            return False

        actual_str = str(actual).lower()
        normalized_keywords = [str(x).lower() for x in keywords]

        if not any(keyword in actual_str for keyword in normalized_keywords):
            return False

    return True


def evaluate_single_event_rule(
    rule: Dict[str, Any],
    event_dict: Dict[str, Any],
    normalized: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    match = rule.get("match", {})
    match_any = rule.get("match_any", {})
    contains_any = rule.get("contains_any", {})

    if match and not _match_exact(match, event_dict, normalized):
        return None

    if match_any and not _match_any(match_any, event_dict, normalized):
        return None

    if contains_any and not _contains_any(contains_any, event_dict, normalized):
        return None

    return {
        "detected": True,
        "rule_id": rule.get("rule_id"),
        "rule_name": rule.get("name"),
        "reason": [f"{rule.get('name')} 조건 만족"],
        "attack_tactic": rule.get("attack", {}).get("tactic"),
        "attack_technique": rule.get("attack", {}).get("technique"),
        "response_guide": rule.get("response_guide", []),
        "severity": rule.get("severity"),
        "score": rule.get("score"),
    }
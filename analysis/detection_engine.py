from typing import Any, Dict, List, Optional

from analysis.rule_loader import load_rules, split_rules_by_type
from analysis.evaluators.single_event import evaluate_single_event_rule
from analysis.evaluators.aggregation import evaluate_aggregation_rule


def evaluate_event(
    event_dict: Dict[str, Any],
    normalized: Dict[str, Any],
    recent_events: Optional[List[Dict[str, Any]]] = None,
) -> Optional[Dict[str, Any]]:
    if recent_events is None:
        recent_events = []

    rules = load_rules()
    grouped = split_rules_by_type(rules)

    # 1) single_event 룰 먼저 평가
    for rule in grouped["single_event"]:
        result = evaluate_single_event_rule(rule, event_dict, normalized)
        if result:
            return result

    # 2) aggregation 룰 평가
    for rule in grouped["aggregation"]:
        result = evaluate_aggregation_rule(rule, event_dict, normalized, recent_events)
        if result:
            return result

    return None
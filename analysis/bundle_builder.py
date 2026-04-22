import json

from analysis.event_normalizer import normalize_event
from analysis.detection_engine import evaluate_event
from analysis.risk_engine import calculate_risk


def build_default_detection() -> dict:
    return {
        "detected": False,
        "rule_id": None,
        "rule_name": None,
        "reason": [],
        "attack_tactic": None,
        "attack_technique": None,
        "response_guide": [],
    }


def build_event_bundle(event, recent_events=None):
    if recent_events is None:
        recent_events = []

    event_dict = {
        "event_time": event.event_time,
        "event_id": str(event.event_id) if event.event_id is not None else None,
        "provider": event.provider,
        "channel": event.channel,
        "level": event.level,
        "computer_name": event.computer_name,
        "username": event.username,
        "source_ip": event.source_ip,
        "target_user": event.target_user,
        "target_host": event.target_host,
        "group_name": event.group_name,
        "logon_type": event.logon_type,
        "service_name": event.service_name,
        "message": event.message,
    }

    normalized = normalize_event(event)

    detection_result = evaluate_event(
        event_dict=event_dict,
        normalized=normalized,
        recent_events=recent_events,
    )

    detection = build_default_detection()
    if detection_result:
        detection.update({
            "detected": detection_result.get("detected", False),
            "rule_id": detection_result.get("rule_id"),
            "rule_name": detection_result.get("rule_name"),
            "reason": detection_result.get("reason", []),
            "attack_tactic": detection_result.get("attack_tactic"),
            "attack_technique": detection_result.get("attack_technique"),
            "response_guide": detection_result.get("response_guide", []),
        })

    risk = calculate_risk(event, normalized, detection)

    try:
        original_event = json.loads(event.raw_json) if event.raw_json else {}
    except (TypeError, json.JSONDecodeError):
        original_event = {"raw_text": event.raw_json} if event.raw_json else {}

    return {
        "event": event_dict,
        "normalized": normalized,
        "detection": detection,
        "risk": risk,
        "raw_json": {
            "original_event": original_event
        },
    }
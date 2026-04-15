import json

from analysis.event_normalizer import normalize_event
from analysis.detection_engine import evaluate_detection


def build_event_bundle(event):
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
    detection, risk = evaluate_detection(event_dict, normalized)

    detection.setdefault("reason", [])
    detection.setdefault("response_guide", [])
    detection.setdefault("detected", False)

    risk.setdefault("base_score", 0)
    risk.setdefault("weight", 0)
    risk.setdefault("final_score", 0)
    risk.setdefault("severity", "none")

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
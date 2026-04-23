import json
from typing import List, Dict, Any, Optional

from analysis.event_normalizer import normalize_event
from analysis.detection_engine import evaluate_event
from analysis.risk_engine import calculate_risk

def build_default_detection() -> dict:
    """탐지되지 않았을 때의 기본 구조"""
    return {
        "detected": False,
        "rule_id": None,
        "rule_name": None,
        "reason": [],
        "attack_tactic": None,
        "attack_technique": None,
        "response_guide": [],
    }

def build_event_bundle(event: Any, recent_events: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    이벤트를 받아 정규화, 탐지, 위험도 계산을 수행하고 최종 DB 저장용 번들을 생성합니다.
    """
    if recent_events is None:
        recent_events = []

    # 1. 원본 데이터로부터 1차 딕셔너리 생성 (DB의 event_json 형태)
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
        "logon_type": str(event.logon_type) if event.logon_type is not None else None,
        "service_name": event.service_name,
        "message": event.message,
    }

    # 2. 이벤트 정규화 (event_normalizer 활용)
    normalized = normalize_event(event)

    # 3. 탐지 엔진 실행 (단일 이벤트 및 집계 이벤트 룰 체크)
    # detection_rules.yaml에 정의된 RULE-001~100 등이 여기서 평가됨
    detection_result = evaluate_event(
        event_dict=event_dict,
        normalized=normalized,
        recent_events=recent_events,
    )

    # 4. 탐지 결과 구조화
    detection = build_default_detection()
    if detection_result and detection_result.get("detected"):
        detection.update({
            "detected": True,
            "rule_id": detection_result.get("rule_id"),
            "rule_name": detection_result.get("rule_name"),
            "reason": detection_result.get("reason", []),
            "attack_tactic": detection_result.get("attack_tactic"),
            "attack_technique": detection_result.get("attack_technique"),
            "response_guide": detection_result.get("response_guide", []),
        })

    # 5. 위험도 계산 (risk_engine 활용)
    # 룰에 설정된 점수(score)와 가중치(weight)를 합산하여 severity 결정
    risk = calculate_risk(event, normalized, detection)

    # 6. Raw JSON 처리 (백업용)
    try:
        original_event = json.loads(event.raw_json) if event.raw_json else {}
    except (TypeError, json.JSONDecodeError):
        original_event = {"raw_text": event.raw_json} if event.raw_json else {}

    # 7. 최종 번들 반환 (DB 최종 저장 형태)
    return {
        "event": event_dict,            # event_json으로 저장됨
        "normalized": normalized,      # normalized_json으로 저장됨
        "detection": detection,        # detection_json으로 저장됨
        "risk": risk,                  # risk_json으로 저장됨
        "raw_json": {
            "original_event": original_event
        },
    }
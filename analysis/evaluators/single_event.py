from typing import Any, Dict, Optional

def _get_field_value(field: str, event_dict: Dict[str, Any], normalized: Dict[str, Any]) -> Any:
    # 우선순위: normalized > event_dict (태우님이 정규화해주는 데이터를 우선 신뢰)
    if field in normalized:
        return normalized.get(field)
    return event_dict.get(field)

def _match_conditions(match: Dict[str, Any], event_dict: Dict[str, Any], normalized: Dict[str, Any]) -> bool:
    for field, expected in match.items():
        actual = _get_field_value(field, event_dict, normalized)
        # 타입 불일치 방지를 위해 문자열 비교 또는 직접 비교
        if str(actual) != str(expected):
            return False
    return True

def evaluate_single_event_rule(
    rule: Dict[str, Any],
    event_dict: Dict[str, Any],
    normalized: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    
    # 1. 룰 매칭 확인
    match = rule.get("match", {})
    if not _match_conditions(match, event_dict, normalized):
        return None

    # 2. 결과 생성을 위한 필드 추출 (대시보드 파싱용)
    base_score = int(rule.get("score", 0))
    severity = rule.get("severity", "low")
    rule_name = rule.get("name")
    
    # 3. 탐지 사유(reason) 동적 생성
    user = normalized.get("username") or event_dict.get("username", "Unknown")
    computer = normalized.get("computer_name") or event_dict.get("computer_name", "Unknown")
    
    reason = f"[{rule_name}] 탐지: {computer} 호스트에서 {user} 계정에 의해 발생"
    
    # 4. 최종 탐지 객체 반환 (DB 저장 형태와 일치)
    return {
        "detected": True,
        "rule_id": rule.get("rule_id"),
        "rule_name": rule_name,
        "reason": [reason],
        "attack_tactic": rule.get("attack", {}).get("tactic"),
        "attack_technique": rule.get("attack", {}).get("technique"),
        "response_guide": rule.get("response_guide", []),
        "risk": {
            "base_score": base_score,
            "weight": 0, # 단일 이벤트는 가중치 0 (기본값)
            "final_score": base_score,
            "severity": severity,
        },
    }
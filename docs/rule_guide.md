# rule 탐지 가이드

## db 최종 저장 형태
```
id 
event_time
ingested_at 
event_id
computer_name 
username 
source_ip 
group_name
message 
raw_json 
event_json (아래 상세 내역 참고)
normalized_json (아래 상세 내역 참고)
detection_json (아래 상세 내역 참고)
risk_json  (아래 상세 내역 참고)
```

* `event_json`
```
"event": {
    "event_time": str | None,
    "event_id": str | None,
    "provider": str | None,
    "channel": str | None,
    "level": str | None,
    "computer_name": str | None,
    "username": str | None,
    "source_ip": str | None,
    "target_user": str | None,
    "target_host": str | None,
    "group_name": str | None,
    "logon_type": str | None,
    "service_name": str | None,
    "message": str | None,
},
```

* `normalized_json`
```
"normalized": {
    "event_type": str | None,
    "username": str | None,
    "target_user": str | None,
    "group_name": str | None,
    "source_ip": str | None,
    "computer_name": str | None,
    "event_id": str | None,
    "host_role": str | None,
    "account_type": str | None,
    "is_admin_account": bool,
    "is_privileged": bool,
    "is_off_hours": bool,
    "logon_type": str | None,
    "logon_type_name": str | None,
    "provider": str | None,
    "channel": str | None,
    "service_name": str | None,
    "target_host": str | None,
},
```

* `detection_json`
```
"detection": {
    "detected": bool,
    "rule_id": str | None,
    "rule_name": str | None,
    "reason": list[str],
    "attack_tactic": str | None,
    "attack_technique": str | None,
    "response_guide": list[str],
},
```

* `risk_json`
```
"risk": {
    "base_score": int,
    "weight": int,
    "final_score": int,
    "severity": str,
},
```


## 탐지 형태
* single_event : 단일 이벤트 탐지
    - `analysis/evaluators/single_event.py` 에서 처리
* aggregation : 여러 조건 조합 탐지
    - `analysis/evaluators/aggregation.py` 에서 처리

## 탐지 함수 기능 분리
   - event_normalizer.py : 무슨 이벤트인지 해석
   - detection_engine.py : 룰 걸리는지 판단
   - risk_engine.py : 위험도 계산 (필요시 사용. 현재는 룰에 추가되어있는 점수만 계산하도록 구성됨)
   - bundle_builder.py = 결과를 event/normalized/detection/risk로 묶음

## 관련 파일들
   - rule_loader.py = YAML 읽는 파일
   - single_event.py = 이벤트 1건 룰 처리
   - aggregation.py = 시간/횟수 기반 룰 처리
   - detection_engine.py = 룰 타입별로 분기해서 실행


* rule `yaml` 파일 형식 예시 (analysis/rules/detection_rules.yaml)
    ```
    rules:
    - rule_id: RULE-001               # 룰 고유 ID
        name: 로그인 실패 급증
        type: aggregation               # single_event(단일 이벤트), aggregation(여러 조건이 조합된 이벤트)
        enabled: true                   # 탐지 안할거면 false. 일반적으로 true

        match:
        event_type: login_failure     # 어떤 이벤트를 대상으로 둘지

        group_by: [username]            # aggregation 에서 어떤 기준으로 조합할지 (username : 사용자 기준, source_ip, computer_name, .... 여러 조건 추가)
        window:
        minutes: 5                    # 몇분 동안의 이벤트를 확인할지
        threshold:
        count_gte: 10                 # 몇건 이상이면 탐지할지 (ex) 10 건 이상

        severity: medium                # 심각도
        score: 50                       # 기본 위험 점수

        score_modifiers:                # 위험도 가중치
        - field: is_admin_account
            op: eq                      # 비교 방식 (ex) = equal
            value: true
            add: 20

        attack:                         # MITRE ATT&CK 정보
        tactic: Credential Access
        technique: T1110

        response_guide:                 # 대응 가이드 (대시보드 출력용?)
        - 계정 잠금 정책 확인
        - source_ip 차단 검토
    ```



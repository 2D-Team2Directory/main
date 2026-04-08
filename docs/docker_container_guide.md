# 도커 컨테이너 가이드 문서
## 세팅에 필요한 파일
* `requirements.txt` : 컨테이너 내부에 필요한 파이썬 패키지
* `Dockerfile` : 필요 항목들을 가지고 실제 컨테이너 구성
* `docker-compose.yml` : 전체 컨테이너 관리 
* 환경 내부에 추가 패키지나 추가 컨테이너 필요할 시 해당 파일 수정

## 실행 방법
* 도커 설치 + 켜져있는 상태(프로그램을 한번이라도 실행시킨 상태)
* 컨테이너 빌드 + 띄우기 : `docker compose up -d --build`
* 전체 컨테이너 다운 : `docker compose down`
* 올라와있는 컨테이너 목록 확인 : `docker ps`

## 환경 페이지
* http://localhost:8000/health : 백엔드 정상적으로 떠있는지 체크하는 페이지. {"status":"ok"} 시 정상.
* http://localhost:8000/docs  : 전체 데이터 결과물들 조회 가능한 페이지
* http://localhost:8501 : 대시보드 접속 페이지

## 설치된 컨테이너
### backend
* 전체 과정 통합 실행 시키는 파트. 수정시 주의
* FastAPI 사용
* SQLite (db) : logstash 의 결과물(json) `./data/events.db` 경로에 저장됨

### dashboard
* Streamlit 사용
* 현재는 db 저장된 이벤트 정보만 간단하게 표시

### collector
* 로그 수집/파싱 기능
* Logstash
    - 클라이언트에서 Winlogbeat 로 전송된 로그 받는 용도
    - 5044 포트
    - 현재 테스트용으로 `sample_events_winlogbeat.jsonl` 파일 읽도록 되어있음
    - windows vm 내부에서 전송시 필요한 winlogbeat.yml 형태 예시
    ```
    winlogbeat.event_logs:
    - name: Security
    - name: System
    - name: Application
    - name: Microsoft-Windows-Sysmon/Operational

    output.logstash:
    hosts: ["<도커호스트IP>:5044"]

    logging.level: info
    ```
* winlogbeat에서 전송(예시 : `collector/sample_events_winlogbeat.jsonl`) 
    ```
    {
        "@timestamp":"2026-04-08T22:12:00.000Z",
        "message":"Special privileges assigned to new logon.",
        "host":{
            "name":"DC-01"
        },
        "log":{
            "level":"information"
        },
        "winlog":{
            "event_id":4672,
            "channel":"Security",
            "provider_name":"Microsoft-Windows-Security-Auditing",
            "event_data":{
                "TargetUserName":"administrator",
                "IpAddress":"192.168.56.10",
                "LogonType":"2"
            }
        }
    }
    ```
* logstash 로 db 에 저장되는 형태로 파싱(예시 : `collector/sample_events_logstash.json`)
    ```
    {
        "event_time": "2026-04-08T22:12:00",                    # 실제 윈도우에서 이벤트가 발생한 시간
        "event_id": "4672",                                     # 윈도우 이벤트 ID
        "provider": "Microsoft-Windows-Security-Auditing",      # 로그 제공자
        "channel": "Security",                                  # Security, Sysmon, System 같은 로그 타입
        "level": "info",                                        # info/warning/critical
        "computer_name": "DC-01",                               # 이벤트가 발생한 시스템
        "username": "administrator",                            # 관련 사용자
        "source_ip": "192.168.56.10",                           # 접속 시도 원본 IP
        "target_user": "administrator",                         # 대상 사용자 계정
        "target_host": "DC-01",                                 # 대상 호스트
        "group_name": "",                                       # 변경 대상 그룹
        "logon_type": "2",                                      # 2 : 로컬 / 3 : 네트워크 / 10 : 원격
        "service_name": "",                                     # Kerberos 혹은 서비스 계정 관련 분석용
        "message": "Special privileges assigned to new logon.", # 보기 쉬운 요약
        "raw_json": "{\"event_id\":\"4672\",\"username\":\"administrator\"}"    # 원본 보존
    },
    ```
* 구조 변경시 `backend/app/main.py` 에서 관련 클래스 구조 일괄적으로 변경 필요 (`init_db()`, `ingest_event()`, `EventIn`, ...)
* `ingest_events_bulk()` 의 경우 sample 테스트용으로 한번에 여러개 넣는 용도로 추가된 것. 실제 기능 구현시 삭제 예정

### analysis
* (컨테이너 구현 안되어있음. 필요시 세팅)

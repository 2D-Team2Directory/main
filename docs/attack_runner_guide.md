# 제공중인 시나리오
1. test ping target : 타겟 지정해서 핑 전달되는지 확인 (수신 확인은 wireshark)
2. 4625 로그인 실패 : login_failure 타입 이벤트 발생용


---

# 공격 시나리오 실행 가이드
대시보드-백엔드의 실행 명령을 통해 공격 머신 내부 `attack-runner` 가 실제 시나리오를 실행

## attack-runner 
* 시나리오 실행 명령 받기 위한 경량 API 서버. 부팅시 자동 실행됨
* 존재하는 시나리오 목록 반환 : 대시보드에 리스트 출력
* 실제 시나리오 실행 및 상태 반환 : 대시보드에 상태 출력
* 실행 로그 파일 저장 : `~/attack-runner/logs/`
* 상태 확인 : `sudo systemctl status attack-runner`

## 시나리오 추가 방법
### 1. 추가 위치 : `~/attack-runner/scenarios/`
* 시나리오 추가 : `<이름>.sh` 파일 추가
```
#!/bin/bash
set -u

RUN_ID="$1"
PARAMS_JSON="$2"

echo "[INFO] scenario started"
echo "[INFO] run_id=$RUN_ID"
echo "[INFO] params=$PARAMS_JSON"

# 실제 공격 로직 작성

echo "[INFO] scenario finished"
exit 0          # 0 : success, 이외 값 : fail
```

* 매개변수 필요할 경우 : `<이름>.meta.json` 파일 추가
    - 기본 매개변수
        - target_ip : 공격 타겟
        - requested_by : 실행자
    - 시나리오 별 매개변수 타입(type)
        - text : 일반 한줄 텍스트
        - password : 비밀번호
        - number : 숫자
        - select : 선택지(드롭다운)
        - checkbox : 체크박스
        - textarea : 여러 줄 텍스트
```
{
    "name": "username",                         # 전달되는 파라미터 값 | (ex) params["username"]
    "label": "사용자명",                          # 대시보드에 보여지는 이름
    "type": "text",                             # 입력 타입
    "required": true,                           # 필수 여부 : true 면 필수
    "default": "fakeuser",                      # 기본 입력값
    "help": "로그인 실패를 발생시킬 대상 사용자명"     # 매개변수 설명
},
{
  "name": "mode",
  "label": "실행 모드",
  "type": "select",
  "required": true,
  "default": "random",
  "options": ["random", "sequential"],
  "help": "동작 방식을 선택"
}
```

### 2. 실행 권한 추가
`chmod +x ~/attack-runner/scenarios/*.sh`

### 3. 파일 추가시 attack_runner 재시작
```
cd ~/attack_runner
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 9000     # 중단 : Ctrl + C
```


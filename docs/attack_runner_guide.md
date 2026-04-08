# 공격 시나리오 실행 가이드
대시보드-백엔드의 실행 명령을 통해 kali 공격 vm 내부 `attack_runner` 가 실제 시나리오를 실행

## Kali VM
* kali vmx 파일 다운로드 (VMware) : https://drive.google.com/file/d/1VDAtxnrpsg1gIVRpLVVuRQ76_9nxZuLs/view?usp=sharing
* ip 확인 : `ip a`

## attack_runner (Kali)
* 시나리오 실행 명령 받기 위한 경량 API 서버. 부팅시 자동 실행됨
* 존재하는 시나리오 목록 반환 : 대시보드에 리스트 출력
* 실제 시나리오 실행 및 상태 반환 : 대시보드에 상태 출력
* 실행 로그 파일 저장 : `~/attack_runner/logs/`
* 환경변수 수정 : `.env.example` 파일명을 `.env`로 수정해서 사용
    * 로컬 환경파일(.env)에 `ATTACK_RUNNER_URL` 값 내부 ip 값으로 수정
    * TOKEN : 로컬 `.env` 의 ATTACK_RUNNER_TOKEN 값과 attack_runner 내부 ATTACK_RUNNER_TOKEN 값을 비교함. 두 값이 같기만 하면 아무 값이나 상관없음
    * attack_runner 내부 토큰 수정
    ```
    sudo nano /etc/systemd/system/attack-runner.service

    # 내부의 아래 값 수정
    Environment="ATTACK_RUNNER_TOKEN=new-secret-token-123"

    # 수정 후 반영
    sudo systemctl daemon-reload
    sudo systemctl restart attack-runner
    ```
* 상태 확인 : `sudo systemctl status attack-runner`

## 사나리오 추가 방법
### 1. 추가 위치
`~/attack_runner/scenarios/`
경로에 `.sh` 파일 추가

### 2. 실행 권한 추가
`chmod +x ~/attack_runner/scenarios/*.sh`

### 3. attack_runner 재시작
```
cd ~/attack_runner
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 9000
```

## 시나리오 파일 형식 예시
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

# Attack Runner MCP Server

Claude Desktop 같은 MCP 클라이언트에서 자연어로 공격 시나리오를
조회·실행·모니터링하기 위한 MCP 서버입니다.

## 사전 준비

- Python 3.10 이상
- Claude Desktop 설치 및 Pro 로그인
- 프로젝트 루트의 `.env`에 다음 키들이 설정되어 있어야 함:
  - `ATTACK_RUNNER_URL`
  - `ATTACK_RUNNER_TOKEN`
  - `ATTACK_REQUESTED_BY`
  - `VICTIM_URL`
- Tailscale에 작업 PC가 가입되어 있어야 함 (attack-runner 접근용)

## 설치

```powershell
cd mcp
pip install -r requirements.txt
```

## 단독 실행 테스트

```powershell
python server.py
```

에러 없이 멈춰있으면 정상 (stdio 대기 상태).
`Ctrl+C`로 종료.

## Claude Desktop 등록

`%APPDATA%\Claude\claude_desktop_config.json` 에 다음 추가:

```json
{
  "mcpServers": {
    "attack-runner": {
      "command": "python",
      "args": ["<프로젝트 절대경로>\\mcp\\server.py"]
    }
  }
}
```

저장 후 Claude Desktop을 트레이에서 **완전 종료** 후 재시작.

## 제공 도구

| 도구 | 용도 |
|---|---|
| `health_check` | API 서버 상태 확인 |
| `list_scenarios` | 시나리오 목록 조회 |
| `run_scenario` | 시나리오 실행 |
| `get_scenario_status` | 실행 상태 조회 |
| `get_scenario_log` | 실행 로그 조회 |
| `list_scenario_runs` | 최근 실행 이력 |
| `list_running_scenarios` | 현재 실행 중인 시나리오 |

## 사용 예시 (Claude 채팅)

- "지금 사용 가능한 공격 시나리오 알려줘"
- "test_ping_target 시나리오 실행해줘"
- "kerberoasting 공격을 victim1 대상으로, 도메인은 lab.local로 실행"
- "방금 실행한 거 로그 보여줘"
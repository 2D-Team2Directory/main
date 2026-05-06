"""
Attack Runner MCP Server

AD 실습 프로젝트의 attack-runner FastAPI를 MCP 도구로 노출.
Claude Desktop 등 MCP 클라이언트에서 자연어로 공격 시나리오를
조회/실행/모니터링할 수 있게 합니다.

환경 변수 (.env에서 자동 로드):
- ATTACK_RUNNER_URL       (기본값: http://100.88.239.108:9000)
- ATTACK_RUNNER_TOKEN     (필수)
- ATTACK_REQUESTED_BY     (기본값: mcp-user)
- VICTIM_URL              (기본 victim IP)
"""
import os
import uuid
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

# ===== .env 자동 로드 (프로젝트 루트의 .env를 찾음) =====
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

# ===== 설정 =====
ATTACK_RUNNER_URL = os.getenv("ATTACK_RUNNER_URL", "http://100.88.239.108:9000")
ATTACK_RUNNER_TOKEN = os.getenv("ATTACK_RUNNER_TOKEN", "lab-secret-token")
ATTACK_REQUESTED_BY = os.getenv("ATTACK_REQUESTED_BY", "mcp-user")
DEFAULT_VICTIM_IP = os.getenv("VICTIM_URL", "100.110.203.60")

HEADERS = {"X-API-Token": ATTACK_RUNNER_TOKEN}
TIMEOUT = 30

# ===== MCP 서버 인스턴스 =====
mcp = FastMCP("attack-runner")


# ---------- 내부 헬퍼 ----------
def _get(path: str, **kwargs) -> Any:
    url = f"{ATTACK_RUNNER_URL}{path}"
    r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, **kwargs)
    r.raise_for_status()
    return r.json()


def _post(path: str, json: dict) -> Any:
    url = f"{ATTACK_RUNNER_URL}{path}"
    r = requests.post(url, headers=HEADERS, json=json, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()


# ---------- 헬스 체크 ----------
@mcp.tool()
def health_check() -> dict:
    """Attack Runner API 서버가 살아있는지 확인합니다."""
    return _get("/health")


# ---------- 시나리오 조회 ----------
@mcp.tool()
def list_scenarios() -> list[dict]:
    """
    사용 가능한 공격 시나리오 전체 목록을 조회합니다.
    각 시나리오는 scenario_id, label, description, params_schema, scenario_type을 포함합니다.

    scenario_type:
    - detection_test: 탐지 룰 동작 확인용 (안전)
    - real_attack: 실제 공격 (kerberoasting, dcsync 등)
    - tools: 정찰/도구
    - general: 일반 (test_ping_target 등)
    """
    return _get("/scenario/list")


# ---------- 시나리오 실행 ----------
@mcp.tool()
def run_scenario(
    scenario_id: str,
    target_ip: str | None = None,
    params: dict | None = None,
) -> dict:
    """
    공격 시나리오를 실행합니다.

    Args:
        scenario_id: 실행할 시나리오 ID. list_scenarios()로 사용 가능 ID 확인.
                     예시: 'kerberoasting', 'asrep_roasting', 'dcsync_golden',
                          'password_spray', 'add_group_member', 'test_ping_target'
        target_ip: 공격 대상 IP. 생략 시 .env의 VICTIM_URL 사용.
                   (내부적으로 params['target_ip']로 전송됩니다)
        params: 시나리오별 추가 파라미터 (dict).
                각 시나리오의 params_schema에 정의된 키를 사용.
                예: {"domain_name": "lab.local", "target_user": "victim1"}
                생략 시 시나리오의 default 값 사용.

    Returns:
        실행 결과 (run_id 포함). 이후 status/log 조회에 run_id 사용.

    Important:
        실제 공격이 victim 머신에 수행됩니다.
        실행 전 사용자에게 시나리오 내용과 대상을 명확히 알리고
        동의를 받은 뒤 호출하세요.
    """
    # attack-runner의 RunScenarioRequest는 최상위에 scenario_id, request_id, params만 받음.
    # target_ip, requested_by는 params 딕셔너리 안에 넣어 전달해야 함.
    merged_params = dict(params) if params else {}
    merged_params.setdefault("target_ip", target_ip or DEFAULT_VICTIM_IP)
    merged_params.setdefault("requested_by", ATTACK_REQUESTED_BY)

    body = {
        "scenario_id": scenario_id,
        "request_id": str(uuid.uuid4()),
        "params": merged_params,
    }
    return _post("/run-scenario", json=body)


# ---------- 실행 상태 / 로그 ----------
@mcp.tool()
def get_scenario_status(run_id: str) -> dict:
    """
    특정 시나리오 실행의 현재 상태를 조회합니다.

    Args:
        run_id: run_scenario()로 받은 run_id

    Returns:
        상태 정보 (running / completed / failed 등)
    """
    return _get(f"/status/{run_id}")


@mcp.tool()
def get_scenario_log(run_id: str, tail: int = 200) -> dict:
    """
    특정 시나리오 실행의 로그를 조회합니다.

    Args:
        run_id: run_scenario()로 받은 run_id
        tail: 끝에서 몇 줄을 가져올지 (기본 200)
    """
    return _get(f"/logs/{run_id}", params={"tail": tail})


# ---------- 실행 이력 ----------
@mcp.tool()
def list_scenario_runs(limit: int = 5) -> list[dict]:
    """
    최근 시나리오 실행 이력을 조회합니다.

    Args:
        limit: 가져올 개수 (기본 5)
    """
    return _get("/scenario-runs", params={"limit": limit})


@mcp.tool()
def list_running_scenarios() -> list[dict]:
    """현재 실행 중인 시나리오 목록을 조회합니다."""
    return _get("/scenario-runs/running")


# ===== 진입점 =====
if __name__ == "__main__":
    mcp.run()
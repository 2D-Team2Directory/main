from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import sqlite3
import os
import requests
import uuid
import json
from datetime import datetime

app = FastAPI()

DB_PATH = os.getenv("DB_PATH", "/data/events.db")
ATTACK_RUNNER_URL = os.getenv("ATTACK_RUNNER_URL", "")
ATTACK_RUNNER_TOKEN = os.getenv("ATTACK_RUNNER_TOKEN", "")


def get_event_type(event_id: Optional[str]) -> str:
    event_id = str(event_id) if event_id is not None else ""

    if event_id == "4624":
        return "login_success"
    if event_id == "4625":
        return "login_failure"
    if event_id == "4720":
        return "account_created"
    if event_id in ["4732", "4756"]:
        return "group_change"
    if event_id in ["4768", "4769"]:
        return "kerberos_request"

    return "unknown"


def get_host_role(computer_name: Optional[str]) -> str:
    if not computer_name:
        return "unknown"

    name = computer_name.lower()

    if "dc" in name:
        return "dc"
    if "server" in name:
        return "server"

    return "client"


def is_admin_name(name: Optional[str]) -> bool:
    if not name:
        return False

    lowered = name.lower()
    admin_keywords = ["administrator", "admin", "domain admin"]

    return any(keyword in lowered for keyword in admin_keywords)


def get_account_type(username: Optional[str], target_user: Optional[str]) -> str:
    name = target_user or username
    if not name:
        return "unknown"

    lowered = name.lower()

    if name.endswith("$"):
        return "machine"
    if "svc" in lowered or "service" in lowered or "sql" in lowered:
        return "service"
    if is_admin_name(name):
        return "admin"

    return "user"


def is_privileged_account(username: Optional[str], target_user: Optional[str]) -> bool:
    account_type = get_account_type(username, target_user)
    return account_type in ["admin", "service"]


def is_off_hours_time(event_time: Optional[str]) -> bool:
    if not event_time:
        return False

    try:
        dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
        hour = dt.hour
        return hour < 8 or hour >= 20
    except Exception:
        return False


def build_event_bundle(event):
    event_part = {
        "id": None,
        "event_time": event.event_time,
        "ingested_at": None,
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

    normalized_part = {
        "event_type": get_event_type(event.event_id),
        "host_role": get_host_role(event.computer_name),
        "account_type": get_account_type(event.username, event.target_user),
        "is_admin_account": is_admin_name(event.target_user or event.username),
        "is_privileged": is_privileged_account(event.username, event.target_user),
        "is_off_hours": is_off_hours_time(event.event_time),
    }

    detection_part = {
        "detected": False,
        "rule_id": None,
        "rule_name": None,
        "reason": [],
        "attack_tactic": None,
        "attack_technique": None,
        "response_guide": [],
    }

    risk_part = {
        "base_score": 0,
        "weight": 0,
        "final_score": 0,
        "severity": "none",
    }

    try:
        original_event = json.loads(event.raw_json) if event.raw_json else {}
    except (TypeError, json.JSONDecodeError):
        original_event = {"raw_text": event.raw_json} if event.raw_json else {}

    raw_part = {
        "original_event": original_event
    }

    return {
        "event": event_part,
        "normalized": normalized_part,
        "detection": detection_part,
        "risk": risk_part,
        "raw_json": raw_part,
    }


# DB
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_time TEXT,
        ingested_at TEXT DEFAULT CURRENT_TIMESTAMP,
        event_id TEXT,
        provider TEXT,
        channel TEXT,
        level TEXT,
        computer_name TEXT,
        username TEXT,
        source_ip TEXT,
        target_user TEXT,
        target_host TEXT,
        group_name TEXT,
        logon_type TEXT,
        service_name TEXT,
        message TEXT,
        raw_json TEXT,
        event_json TEXT,
        normalized_json TEXT,
        detection_json TEXT,
        risk_json TEXT
    )
    """)

    for sql in [
        "ALTER TABLE events ADD COLUMN event_json TEXT",
        "ALTER TABLE events ADD COLUMN normalized_json TEXT",
        "ALTER TABLE events ADD COLUMN detection_json TEXT",
        "ALTER TABLE events ADD COLUMN risk_json TEXT",
    ]:
        try:
            cur.execute(sql)
        except sqlite3.OperationalError:
            pass

    conn.commit()
    conn.close()


@app.on_event("startup")
def startup():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    init_db()


class EventIn(BaseModel):
    event_time: Optional[str] = None
    event_id: Optional[str] = None
    provider: Optional[str] = None
    channel: Optional[str] = None
    level: Optional[str] = None
    computer_name: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None
    target_user: Optional[str] = None
    target_host: Optional[str] = None
    group_name: Optional[str] = None
    logon_type: Optional[str] = None
    service_name: Optional[str] = None
    message: Optional[str] = None
    raw_json: Optional[str] = None


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/events")
def ingest_event(event: EventIn):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    bundle = build_event_bundle(event)

    cur.execute("""
        INSERT INTO events (
            event_time, event_id, provider, channel, level,
            computer_name, username, source_ip,
            target_user, target_host, group_name,
            logon_type, service_name, message, raw_json,
            event_json, normalized_json, detection_json, risk_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event.event_time,
        event.event_id,
        event.provider,
        event.channel,
        event.level,
        event.computer_name,
        event.username,
        event.source_ip,
        event.target_user,
        event.target_host,
        event.group_name,
        event.logon_type,
        event.service_name,
        event.message,
        event.raw_json,
        json.dumps(bundle["event"], ensure_ascii=False),
        json.dumps(bundle["normalized"], ensure_ascii=False),
        json.dumps(bundle["detection"], ensure_ascii=False),
        json.dumps(bundle["risk"], ensure_ascii=False),
    ))

    conn.commit()
    conn.close()
    return {"result": "saved"}


@app.get("/events")
def list_events(limit: int = 50):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM events
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


@app.post("/events/bulk")
def ingest_events_bulk(events: List[EventIn]):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    for event in events:
        bundle = build_event_bundle(event)

        cur.execute("""
            INSERT INTO events (
                event_time, event_id, provider, channel, level,
                computer_name, username, source_ip,
                target_user, target_host, group_name,
                logon_type, service_name, message, raw_json,
                event_json, normalized_json, detection_json, risk_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.event_time,
            event.event_id,
            event.provider,
            event.channel,
            event.level,
            event.computer_name,
            event.username,
            event.source_ip,
            event.target_user,
            event.target_host,
            event.group_name,
            event.logon_type,
            event.service_name,
            event.message,
            event.raw_json,
            json.dumps(bundle["event"], ensure_ascii=False),
            json.dumps(bundle["normalized"], ensure_ascii=False),
            json.dumps(bundle["detection"], ensure_ascii=False),
            json.dumps(bundle["risk"], ensure_ascii=False),
        ))

    conn.commit()
    conn.close()
    return {"result": "saved", "count": len(events)}


# 공격 시나리오 실행
class ScenarioRunRequest(BaseModel):
    scenario_id: str
    params: Optional[Dict[str, Any]] = None


@app.post("/scenario/run")
def run_scenario(req: ScenarioRunRequest):
    if not ATTACK_RUNNER_URL:
        return {
            "result": "error",
            "message": "ATTACK_RUNNER_URL is not configured"
        }

    run_id = f"run-{uuid.uuid4().hex[:8]}"

    body = {
        "scenario_id": req.scenario_id,
        "request_id": run_id,
        "params": req.params or {}
    }

    try:
        res = requests.post(
            f"{ATTACK_RUNNER_URL}/run-scenario",
            json=body,
            headers={"X-API-Token": ATTACK_RUNNER_TOKEN},
            timeout=10
        )
        res.raise_for_status()
        data = res.json()

        return {
            "result": "accepted",
            "run_id": data.get("run_id", run_id),
            "status": data.get("status", "running"),
            "scenario_id": data.get("scenario_id", req.scenario_id)
        }

    except requests.RequestException as e:
        return {
            "result": "error",
            "message": f"Failed to call attack runner: {e}"
        }


@app.get("/scenario/status/{run_id}")
def scenario_status(run_id: str):
    if not ATTACK_RUNNER_URL:
        return {
            "result": "error",
            "message": "ATTACK_RUNNER_URL is not configured"
        }

    try:
        res = requests.get(
            f"{ATTACK_RUNNER_URL}/status/{run_id}",
            headers={"X-API-Token": ATTACK_RUNNER_TOKEN},
            timeout=10
        )
        res.raise_for_status()
        return res.json()

    except requests.RequestException as e:
        return {
            "result": "error",
            "message": f"Failed to get scenario status: {e}"
        }


@app.get("/scenario/list")
def scenario_list():
    if not ATTACK_RUNNER_URL:
        return {
            "result": "error",
            "message": "ATTACK_RUNNER_URL is not configured"
        }

    try:
        res = requests.get(
            f"{ATTACK_RUNNER_URL}/scenario/list",
            headers={"X-API-Token": ATTACK_RUNNER_TOKEN},
            timeout=10
        )
        res.raise_for_status()
        return res.json()

    except requests.RequestException as e:
        return {
            "result": "error",
            "message": f"Failed to get scenario list: {e}"
        }
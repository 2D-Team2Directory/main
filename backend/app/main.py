from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional, List
import sqlite3
import os

app = FastAPI()

DB_PATH = os.getenv("DB_PATH", "/data/events.db")


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
        raw_json TEXT
    )
    """)
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

    cur.execute("""
        INSERT INTO events (
            event_time, event_id, provider, channel, level,
            computer_name, username, source_ip,
            target_user, target_host, group_name,
            logon_type, service_name, message, raw_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        event.raw_json
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
        cur.execute("""
            INSERT INTO events (
                event_time, event_id, provider, channel, level,
                computer_name, username, source_ip,
                target_user, target_host, group_name,
                logon_type, service_name, message, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            event.raw_json
        ))

    conn.commit()
    conn.close()
    return {"result": "saved", "count": len(events)}
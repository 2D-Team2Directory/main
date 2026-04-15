import json

from app.db import get_conn
from analysis.bundle_builder import build_event_bundle


def save_event(event):
    conn = get_conn()
    cur = conn.cursor()

    bundle = build_event_bundle(event)

    cur.execute("""
        INSERT INTO events (
            event_time, event_id,
            computer_name, username, source_ip,
            group_name, message, raw_json,
            event_json, normalized_json, detection_json, risk_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event.event_time,
        event.event_id,
        event.computer_name,
        event.username,
        event.source_ip,
        event.group_name,
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


def list_events(limit: int = 50):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT * FROM events
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows
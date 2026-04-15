import os
import sqlite3

DB_PATH = os.getenv("DB_PATH", "/data/events.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_time TEXT,
        ingested_at TEXT DEFAULT CURRENT_TIMESTAMP,
        event_id TEXT,
        computer_name TEXT,
        username TEXT,
        source_ip TEXT,
        group_name TEXT,
        message TEXT,
        raw_json TEXT,
        event_json TEXT,
        normalized_json TEXT,
        detection_json TEXT,
        risk_json TEXT
    );
    """)
    conn.commit()
    conn.close()
import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import psycopg
from psycopg.rows import dict_row
from pydantic import BaseModel


DATABASE_URL = os.getenv("DATABASE_URL")
DB_PATH = os.getenv("SQLITE_PATH", "/tmp/nadacs-audit.db")

app = FastAPI(title="NADACS Audit Log", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AuditEvent(BaseModel):
    event_type: str
    payload: dict[str, Any]


def using_postgres() -> bool:
    return bool(DATABASE_URL)


def connect_sqlite():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          event_type TEXT NOT NULL,
          payload TEXT NOT NULL,
          previous_hash TEXT NOT NULL,
          event_hash TEXT NOT NULL,
          created_at TEXT NOT NULL
        )
        """
    )
    return conn


def connect_postgres():
    conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_events (
          id BIGSERIAL PRIMARY KEY,
          event_type TEXT NOT NULL,
          payload JSONB NOT NULL,
          previous_hash TEXT NOT NULL,
          event_hash TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def connect():
    return connect_postgres() if using_postgres() else connect_sqlite()


def latest_hash(conn) -> str:
    row = conn.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
    return row["event_hash"] if row else "GENESIS"


def hash_event(event_type: str, payload: dict[str, Any], previous_hash: str, created_at: str) -> str:
    canonical = json.dumps(
        {
            "event_type": event_type,
            "payload": payload,
            "previous_hash": previous_hash,
            "created_at": created_at,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def normalize_created_at(value: Any) -> str:
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


@app.get("/health")
def health():
    with connect() as conn:
        count = conn.execute("SELECT COUNT(*) AS count FROM audit_events").fetchone()["count"]
    return {"status": "ok", "events": count}


@app.post("/events")
def create_event(event: AuditEvent):
    created_at = datetime.now(timezone.utc).isoformat()
    with connect() as conn:
        previous_hash = latest_hash(conn)
        event_hash = hash_event(event.event_type, event.payload, previous_hash, created_at)
        payload = json.dumps(event.payload, sort_keys=True)
        if using_postgres():
            cursor = conn.execute(
                """
                INSERT INTO audit_events (event_type, payload, previous_hash, event_hash, created_at)
                VALUES (%s, %s::jsonb, %s, %s, %s)
                RETURNING id
                """,
                (event.event_type, payload, previous_hash, event_hash, created_at),
            )
            event_id = cursor.fetchone()["id"]
        else:
            cursor = conn.execute(
                """
                INSERT INTO audit_events (event_type, payload, previous_hash, event_hash, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (event.event_type, payload, previous_hash, event_hash, created_at),
            )
            event_id = cursor.lastrowid
        conn.commit()
        return {
            "id": event_id,
            "event_type": event.event_type,
            "previous_hash": previous_hash,
            "event_hash": event_hash,
            "created_at": created_at,
        }


@app.get("/events")
def list_events(limit: int = 100):
    with connect() as conn:
        if using_postgres():
            rows = conn.execute(
                "SELECT * FROM audit_events ORDER BY id DESC LIMIT %s",
                (min(limit, 500),),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?",
                (min(limit, 500),),
            ).fetchall()
    return [dict(row) for row in rows]


@app.get("/verify")
def verify_chain():
    with connect() as conn:
        rows = conn.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()

    previous = "GENESIS"
    for row in rows:
        payload = row["payload"] if isinstance(row["payload"], dict) else json.loads(row["payload"])
        created_at = normalize_created_at(row["created_at"])
        expected = hash_event(row["event_type"], payload, previous, created_at)
        if row["previous_hash"] != previous or row["event_hash"] != expected:
            return {"valid": False, "failed_at": row["id"]}
        previous = row["event_hash"]
    return {"valid": True, "events": len(rows)}

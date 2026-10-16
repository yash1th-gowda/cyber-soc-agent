"""SQLite persistence (stdlib sqlite3). One connection per Database instance
(an earlier path-keyed cache merged separate :memory: DBs -- fixed)."""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from typing import Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source TEXT NOT NULL,
    event_type TEXT NOT NULL, severity TEXT NOT NULL, source_ip TEXT, destination_ip TEXT,
    username TEXT, hostname TEXT, process TEXT, command TEXT, bytes_transferred INTEGER,
    message TEXT, raw_event TEXT, indicators TEXT, created_at TEXT DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY, rule TEXT NOT NULL, classification TEXT NOT NULL,
    severity TEXT NOT NULL, confidence REAL NOT NULL, event_ids TEXT NOT NULL,
    evidence TEXT NOT NULL, reasoning TEXT, indicators TEXT, status TEXT NOT NULL,
    incident_id TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL,
    confidence REAL NOT NULL, status TEXT NOT NULL, event_ids TEXT, alert_ids TEXT,
    entities TEXT, timeline TEXT, attack_chain TEXT, mitre_techniques TEXT, evidence TEXT,
    risk_score INTEGER, investigation TEXT, recommendations TEXT, response_actions TEXT,
    created_at TEXT);
CREATE TABLE IF NOT EXISTS response_actions (
    action_id TEXT PRIMARY KEY, action_type TEXT NOT NULL, target TEXT NOT NULL,
    incident_id TEXT NOT NULL, reason TEXT, status TEXT NOT NULL, approved_by TEXT,
    result TEXT, created_at TEXT, decided_at TEXT);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT DEFAULT (datetime('now')),
    actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT, result TEXT, details TEXT);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_username ON events(username);
CREATE INDEX IF NOT EXISTS idx_events_hostname ON events(hostname);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id);
"""

_ENTITY_FIELDS = {"source_ip", "username", "hostname", "destination_ip"}


class Database:
    def __init__(self, path: str = "cyber_soc.db"):
        self.path = path
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._lock = threading.Lock()

        self._lock = threading.Lock()
        self._closed = False

        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        """Close the SQLite connection safely; repeated calls are harmless."""
        with self._lock:
            if not self._closed:
                self._conn.close()
                self._closed = True

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    @contextmanager
    def cursor(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            if self._closed:
                raise RuntimeError("Database is closed")

            cur = self._conn.cursor()
            try:
                yield cur
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            finally:
                cur.close()

    # ---- events ----
    def insert_event(self, e: dict) -> None:
        with self.cursor() as cur:
            cur.execute(
                """INSERT OR REPLACE INTO events (event_id,timestamp,source,event_type,severity,
                source_ip,destination_ip,username,hostname,process,command,bytes_transferred,
                message,raw_event,indicators) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (e["event_id"], e["timestamp"], e["source"], e["event_type"], e["severity"],
                 e.get("source_ip"), e.get("destination_ip"), e.get("username"), e.get("hostname"),
                 e.get("process"), e.get("command"), e.get("bytes_transferred"), e.get("message", ""),
                 json.dumps(e.get("raw_event", {})), json.dumps(e.get("indicators", []))))

    def get_event(self, event_id: str):
        with self.cursor() as cur:
            cur.execute("SELECT * FROM events WHERE event_id = ?", (event_id,))
            r = cur.fetchone()
            return _event(r) if r else None

    def list_events(self, limit: int = 500) -> list:
        with self.cursor() as cur:
            cur.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,))
            return [_event(r) for r in cur.fetchall()]

    def recent_events_for_entity(self, field_name, value, window_seconds, before_timestamp) -> list:
        """Backward-only lookback."""
        if value is None:
            return []
        if field_name not in _ENTITY_FIELDS:
            raise ValueError(f"field_name must be one of {_ENTITY_FIELDS}")
        with self.cursor() as cur:
            cur.execute(
                f"""SELECT * FROM events WHERE {field_name} = ?
                    AND datetime(timestamp) <= datetime(?)
                    AND datetime(timestamp) >= datetime(?, ?) ORDER BY timestamp ASC""",
                (value, before_timestamp, before_timestamp, f"-{window_seconds} seconds"))
            return [_event(r) for r in cur.fetchall()]

    def events_in_symmetric_window(self, field_name, value, window_seconds, center_timestamp) -> list:
        """Backward AND forward lookback; makes window rules robust to
        out-of-order ingestion (see tests/unit/test_correctness.py)."""
        if value is None:
            return []
        if field_name not in _ENTITY_FIELDS:
            raise ValueError(f"field_name must be one of {_ENTITY_FIELDS}")
        with self.cursor() as cur:
            cur.execute(
                f"""SELECT * FROM events WHERE {field_name} = ?
                    AND datetime(timestamp) >= datetime(?, ?)
                    AND datetime(timestamp) <= datetime(?, ?) ORDER BY timestamp ASC""",
                (value, center_timestamp, f"-{window_seconds} seconds",
                 center_timestamp, f"+{window_seconds} seconds"))
            return [_event(r) for r in cur.fetchall()]

    # ---- alerts ----
    def insert_alert(self, a: dict) -> None:
        with self.cursor() as cur:
            cur.execute(
                """INSERT OR REPLACE INTO alerts (alert_id,rule,classification,severity,confidence,
                event_ids,evidence,reasoning,indicators,status,incident_id,created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (a["alert_id"], a["rule"], a["classification"], a["severity"], a["confidence"],
                 json.dumps(a["event_ids"]), json.dumps(a["evidence"]),
                 json.dumps(a.get("reasoning", [])), json.dumps(a.get("indicators", [])),
                 a.get("status", "open"), a.get("incident_id"), a.get("created_at")))

    def list_alerts(self, limit: int = 500) -> list:
        with self.cursor() as cur:
            cur.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,))
            return [_alert(r) for r in cur.fetchall()]

    def alerts_for_rule(self, rule: str) -> list:
        with self.cursor() as cur:
            cur.execute("SELECT * FROM alerts WHERE rule = ?", (rule,))
            return [_alert(r) for r in cur.fetchall()]

    def set_alert_incident(self, alert_id: str, incident_id: str) -> None:
        with self.cursor() as cur:
            cur.execute("UPDATE alerts SET incident_id=?, status='investigating' WHERE alert_id=?",
                        (incident_id, alert_id))

    def unassigned_alerts(self) -> list:
        with self.cursor() as cur:
            cur.execute("SELECT * FROM alerts WHERE incident_id IS NULL ORDER BY created_at ASC")
            return [_alert(r) for r in cur.fetchall()]

    # ---- incidents ----
    def insert_incident(self, i: dict) -> None:
        with self.cursor() as cur:
            cur.execute(
                """INSERT OR REPLACE INTO incidents (incident_id,title,severity,confidence,status,
                event_ids,alert_ids,entities,timeline,attack_chain,mitre_techniques,evidence,
                risk_score,investigation,recommendations,response_actions,created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (i["incident_id"], i["title"], i["severity"], i["confidence"], i["status"],
                 json.dumps(i["event_ids"]), json.dumps(i["alert_ids"]),
                 json.dumps(i.get("entities", {})), json.dumps(i.get("timeline", [])),
                 json.dumps(i.get("attack_chain", [])), json.dumps(i.get("mitre_techniques", [])),
                 json.dumps(i.get("evidence", [])), i.get("risk_score"),
                 json.dumps(i.get("investigation")), json.dumps(i.get("recommendations", [])),
                 json.dumps(i.get("response_actions", [])), i.get("created_at")))

    def get_incident(self, incident_id: str):
        with self.cursor() as cur:
            cur.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
            r = cur.fetchone()
            return _incident(r) if r else None

    def list_incidents(self, limit: int = 200) -> list:
        with self.cursor() as cur:
            cur.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,))
            return [_incident(r) for r in cur.fetchall()]

    # ---- response actions ----
    def insert_response_action(self, a: dict) -> None:
        with self.cursor() as cur:
            cur.execute(
                """INSERT OR REPLACE INTO response_actions (action_id,action_type,target,incident_id,
                reason,status,approved_by,result,created_at,decided_at) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (a["action_id"], a["action_type"], a["target"], a["incident_id"], a.get("reason"),
                 a["status"], a.get("approved_by"), a.get("result"), a.get("created_at"),
                 a.get("decided_at")))

    def get_response_action(self, action_id: str):
        with self.cursor() as cur:
            cur.execute("SELECT * FROM response_actions WHERE action_id = ?", (action_id,))
            r = cur.fetchone()
            return dict(r) if r else None

    # ---- audit ----
    def audit(self, actor, action, target="", result="", details=None) -> None:
        with self.cursor() as cur:
            cur.execute("INSERT INTO audit_log (actor,action,target,result,details) VALUES (?,?,?,?,?)",
                        (actor, action, target, result, json.dumps(details or {})))

    def list_audit(self, limit: int = 200) -> list:
        with self.cursor() as cur:
            cur.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(r) for r in cur.fetchall()]

    def reset(self) -> None:
        with self.cursor() as cur:
            for t in ("events", "alerts", "incidents", "response_actions", "audit_log"):
                cur.execute(f"DELETE FROM {t}")


def _event(row):
    d = dict(row)
    d["raw_event"] = json.loads(d["raw_event"] or "{}")
    d["indicators"] = json.loads(d["indicators"] or "[]")
    return d


def _alert(row):
    d = dict(row)
    for f in ("event_ids", "evidence", "reasoning", "indicators"):
        d[f] = json.loads(d[f] or "[]")
    return d


def _incident(row):
    d = dict(row)
    defaults = {"entities": {}, "investigation": None}
    for f in ("event_ids", "alert_ids", "entities", "timeline", "attack_chain",
              "mitre_techniques", "evidence", "investigation", "recommendations", "response_actions"):
        raw = d[f]
        d[f] = json.loads(raw) if raw is not None else defaults.get(f, [])
    return d

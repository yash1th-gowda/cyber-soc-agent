"""Time-window + shared-entity correlation (union-find). Not a graph DB."""
from __future__ import annotations

from datetime import datetime, timedelta

CORRELATION_WINDOW = timedelta(minutes=15)
ENTITY_FIELDS = (
    "source_ip",
    "destination_ip",
    "username",
    "hostname",
)
ATTACK_CHAIN_ORDER = ["BRUTE_FORCE", "POSSIBLE_CREDENTIAL_COMPROMISE", "CREDENTIAL_DUMPING_TOOL",
                      "SUSPICIOUS_POWERSHELL", "PRIVILEGE_ESCALATION", "POSSIBLE_LATERAL_MOVEMENT",
                      "SUSPICIOUS_EXTERNAL_CONNECTION"]
ATTACK_CHAIN_LABELS = {
    "BRUTE_FORCE": "Brute Force", "POSSIBLE_CREDENTIAL_COMPROMISE": "Valid Account (Possible Compromise)",
    "CREDENTIAL_DUMPING_TOOL": "Credential Dumping", "SUSPICIOUS_POWERSHELL": "PowerShell Execution",
    "PRIVILEGE_ESCALATION": "Privilege Escalation", "POSSIBLE_LATERAL_MOVEMENT": "Lateral Movement",
    "SUSPICIOUS_EXTERNAL_CONNECTION": "External Connection"}
SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _entities_of(alert, db):
    ents = {f: set() for f in ENTITY_FIELDS}
    for eid in alert["evidence"]:
        ev = db.get_event(eid)
        if ev:
            for f in ENTITY_FIELDS:
                if ev.get(f):
                    ents[f].add(ev[f])
    return ents


def _shares(a, b):
    return any(a[f] & b[f] for f in ENTITY_FIELDS)


def _alert_time(alert, db):
    """Time of the alert = earliest timestamp among its evidence EVENTS (not wall-clock ingest time,
    which made historical replays always look 'in window')."""
    ts = [datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")) for e in
          (db.get_event(i) for i in alert["evidence"]) if e]
    ts = [t.replace(tzinfo=None) for t in ts]
    return min(ts) if ts else None


def _within(ta, tb):
    if ta is None or tb is None:
        return True
    return abs(ta - tb) <= CORRELATION_WINDOW


def correlate(alerts: list, db) -> list:
    n = len(alerts)
    parent = list(range(n))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    cache = [_entities_of(a, db) for a in alerts]
    times = [_alert_time(a, db) for a in alerts]
    for i in range(n):
        for j in range(i + 1, n):
            if _within(times[i], times[j]) and _shares(cache[i], cache[j]):
                parent[find(i)] = find(j)
    clusters = {}
    for i in range(n):
        clusters.setdefault(find(i), []).append(alerts[i])
    return list(clusters.values())


def build_incident_from_cluster(cluster: list, db) -> dict:
    event_ids = sorted({e for a in cluster for e in a["evidence"]})
    events = sorted([e for e in (db.get_event(i) for i in event_ids) if e], key=lambda e: e["timestamp"])
    ents = {f: set() for f in ENTITY_FIELDS}
    for a in cluster:
        ea = _entities_of(a, db)
        for f in ENTITY_FIELDS:
            ents[f] |= ea[f]
    ents = {k: sorted(v) for k, v in ents.items() if v}
    timeline = [{"timestamp": e["timestamp"], "event_id": e["event_id"],
                 "description": e.get("message") or f"{e['event_type']} on {e.get('hostname') or e.get('source_ip')}"}
                for e in events]
    fired = [a["rule"] for a in cluster]
    chain = [ATTACK_CHAIN_LABELS[r] for r in ATTACK_CHAIN_ORDER if r in fired]
    severity = max((a["severity"] for a in cluster), key=lambda s: SEVERITY_RANK[s])
    confidence = round(sum(a["confidence"] for a in cluster) / len(cluster), 2)
    title = (f"Possible Multi-Stage Incident: {' -> '.join(chain) if chain else 'Correlated Activity'}"
             if len(cluster) > 1 else cluster[0]["classification"].replace("_", " ").title())
    return {"title": title, "severity": severity, "confidence": confidence, "status": "new",
            "event_ids": event_ids, "alert_ids": [a["alert_id"] for a in cluster], "entities": ents,
            "timeline": timeline, "attack_chain": chain, "evidence": event_ids}

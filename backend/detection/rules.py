"""Deterministic detection rules. Each: (event, db) -> alert-shaped dict | None.
Every alert names the event IDs that justify it."""
from __future__ import annotations

from typing import Optional

INTERNAL_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.",
                     "172.31.", "192.168.", "127.")
POWERSHELL_SUSPICIOUS_TOKENS = (
    "-enc", "-encodedcommand", "-e ", "iex", "invoke-expression", "downloadstring",
    "downloadfile", "-nop", "-noprofile", "-windowstyle hidden", "-w hidden", "bypass",
    "frombase64string", "net.webclient")
CREDENTIAL_DUMP_TOKENS = ("mimikatz", "lsass", "procdump", "sekurlsa", "ntdsutil", "secretsdump")
PRIVILEGE_GROUPS = ("administrators", "domain admins", "enterprise admins", "root", "sudoers")

BRUTE_FORCE_WINDOW_SECONDS = 600
BRUTE_FORCE_THRESHOLD = 5
CRED_COMPROMISE_WINDOW_SECONDS = 600
CRED_COMPROMISE_FAILURE_THRESHOLD = 3
EXTERNAL_CONN_LOOKBACK_SECONDS = 900
LARGE_TRANSFER_BYTES = 50_000_000
LATERAL_MOVEMENT_WINDOW_SECONDS = 600
LATERAL_MOVEMENT_DISTINCT_HOSTS = 4


def _is_internal(ip: Optional[str]) -> bool:
    return True if not ip else ip.startswith(INTERNAL_PREFIXES)


def _ids(events: list) -> list:
    return [e["event_id"] for e in events]


def _already_alerted(db, rule: str, evidence_ids: set) -> bool:
    """Dedup: a symmetric window lets several events in one burst reach the threshold;
    skip if an existing alert for this rule overlaps this evidence."""
    return any(evidence_ids & set(a["evidence"]) for a in db.alerts_for_rule(rule))


def rule_brute_force(event, db):
    if event["event_type"] != "login_failure" or not event.get("source_ip"):
        return None
    # Symmetric window: regression fix -- 5 failures ingested out of order used to give 0 alerts.
    window = db.events_in_symmetric_window("source_ip", event["source_ip"],
                                           BRUTE_FORCE_WINDOW_SECONDS, event["timestamp"])
    failures = [e for e in window if e["event_type"] == "login_failure"]
    if len(failures) < BRUTE_FORCE_THRESHOLD:
        return None
    ev = _ids(failures)
    if _already_alerted(db, "BRUTE_FORCE", set(ev)):
        return None
    users = sorted({e.get("username") for e in failures if e.get("username")})
    return {"rule": "BRUTE_FORCE", "classification": "suspicious_authentication_activity",
            "severity": "high", "confidence": 0.85, "event_ids": ev, "evidence": ev,
            "indicators": [event["source_ip"]],
            "reasoning": [f"{len(failures)} failed authentication attempts from {event['source_ip']} "
                          f"within a {BRUTE_FORCE_WINDOW_SECONDS}s window (events {', '.join(ev)}).",
                          f"Target account(s): {', '.join(users) if users else 'unknown'}."]}


def rule_credential_compromise(event, db):
    """KNOWN LIMITATION: evaluates only when a login_success is ingested. Robust to the
    failures arriving out of order, not to the success arriving before some failures."""
    if event["event_type"] != "login_success" or not event.get("source_ip"):
        return None
    window = db.events_in_symmetric_window("source_ip", event["source_ip"],
                                           CRED_COMPROMISE_WINDOW_SECONDS, event["timestamp"])
    failures = [e for e in window if e["event_type"] == "login_failure"]
    if len(failures) < CRED_COMPROMISE_FAILURE_THRESHOLD:
        return None
    ev = _ids(failures) + [event["event_id"]]
    return {"rule": "POSSIBLE_CREDENTIAL_COMPROMISE", "classification": "possible_credential_compromise",
            "severity": "critical", "confidence": 0.88, "event_ids": ev, "evidence": ev,
            "indicators": [event["source_ip"], event.get("username")],
            "reasoning": [f"Account '{event.get('username')}' authenticated successfully from "
                          f"{event['source_ip']} at {event['timestamp']} after {len(failures)} failed "
                          f"attempts from the same source within {CRED_COMPROMISE_WINDOW_SECONDS}s.",
                          "Consistent with successful brute-force/credential stuffing, but could also be a "
                          "legitimate user who mistyped a password -- flagged for investigation, not confirmed."]}


def rule_suspicious_powershell(event, db):
    if event["event_type"] != "process_create":
        return None
    process = (event.get("process") or "").lower()
    command = (event.get("command") or "").lower()
    if "powershell" not in process:
        return None
    dump = [t for t in CREDENTIAL_DUMP_TOKENS if t in command]
    hits = [t for t in POWERSHELL_SUSPICIOUS_TOKENS if t in command]
    if dump:
        return {"rule": "CREDENTIAL_DUMPING_TOOL", "classification": "possible_credential_dumping",
                "severity": "critical", "confidence": 0.92, "event_ids": [event["event_id"]],
                "evidence": [event["event_id"]], "indicators": dump,
                "reasoning": [f"Process '{event.get('process')}' on {event.get('hostname')} executed a command "
                              f"referencing credential-dumping tooling ({', '.join(dump)}): event {event['event_id']}."]}
    if hits:
        return {"rule": "SUSPICIOUS_POWERSHELL", "classification": "suspicious_powershell_execution",
                "severity": "high", "confidence": 0.75, "event_ids": [event["event_id"]],
                "evidence": [event["event_id"]], "indicators": hits,
                "reasoning": [f"PowerShell on {event.get('hostname')} used obfuscation/download indicators "
                              f"({', '.join(hits)}) in event {event['event_id']}."]}
    return None


def rule_privilege_escalation(event, db):
    if event["event_type"] not in ("privilege_change", "group_membership_change"):
        return None
    text = f"{(event.get('message') or '').lower()} {(event.get('command') or '').lower()}"
    if not any(g in text for g in PRIVILEGE_GROUPS):
        return None
    return {"rule": "PRIVILEGE_ESCALATION", "classification": "privilege_escalation",
            "severity": "high", "confidence": 0.8, "event_ids": [event["event_id"]],
            "evidence": [event["event_id"]], "indicators": [event.get("username")],
            "reasoning": [f"Account '{event.get('username')}' added to a privileged group on "
                          f"{event.get('hostname')} (event {event['event_id']}): \"{event.get('message')}\"."]}


def rule_suspicious_external_connection(event, db):
    if event["event_type"] != "network_connection":
        return None
    dest = event.get("destination_ip")
    if _is_internal(dest):
        return None
    reasons, evidence, confidence, severity = [], [event["event_id"]], 0.55, "medium"
    if event.get("hostname"):
        hw = db.recent_events_for_entity("hostname", event["hostname"],
                                         EXTERNAL_CONN_LOOKBACK_SECONDS, event["timestamp"])
        ps = [e for e in hw if e["event_type"] == "process_create"
              and "powershell" in (e.get("process") or "").lower()]
        if ps:
            evidence += _ids(ps)
            confidence, severity = 0.8, "high"
            reasons.append(f"External connection to {dest} from {event['hostname']} followed PowerShell "
                           f"execution on the same host within {EXTERNAL_CONN_LOOKBACK_SECONDS}s "
                           f"(events {', '.join(_ids(ps))}).")
    out = event.get("bytes_transferred") or 0
    if out >= LARGE_TRANSFER_BYTES:
        confidence = min(0.95, confidence + 0.15)
        severity = "high"
        reasons.append(f"Outbound transfer of {out:,} bytes to external host {dest}.")
    if not reasons:
        reasons.append(f"Outbound connection to non-internal address {dest} (event {event['event_id']}); "
                       "no corroborating indicators found.")
    return {"rule": "SUSPICIOUS_EXTERNAL_CONNECTION", "classification": "suspicious_external_connection",
            "severity": severity, "confidence": confidence, "event_ids": evidence, "evidence": evidence,
            "indicators": [dest], "reasoning": reasons}


def rule_lateral_movement(event, db):
    if event["event_type"] not in ("login_success", "network_connection") or not event.get("username"):
        return None
    window = db.events_in_symmetric_window("username", event["username"],
                                           LATERAL_MOVEMENT_WINDOW_SECONDS, event["timestamp"])
    rel = [e for e in window if e["event_type"] in ("login_success", "network_connection")]
    hosts = sorted({e.get("hostname") or e.get("destination_ip") for e in rel
                    if (e.get("hostname") or e.get("destination_ip"))})
    if len(hosts) < LATERAL_MOVEMENT_DISTINCT_HOSTS:
        return None
    if _already_alerted(db, "POSSIBLE_LATERAL_MOVEMENT", set(_ids(rel))):
        return None
    return {"rule": "POSSIBLE_LATERAL_MOVEMENT", "classification": "possible_lateral_movement",
            "severity": "high", "confidence": 0.7, "event_ids": _ids(rel), "evidence": _ids(rel),
            "indicators": hosts,
            "reasoning": [f"Account '{event['username']}' accessed {len(hosts)} distinct hosts "
                          f"({', '.join(str(h) for h in hosts)}) within {LATERAL_MOVEMENT_WINDOW_SECONDS}s "
                          f"(events {', '.join(_ids(rel))})."]}


RULES = [rule_brute_force, rule_credential_compromise, rule_suspicious_powershell,
         rule_privilege_escalation, rule_suspicious_external_connection, rule_lateral_movement]


def evaluate_event(event: dict, db) -> list:
    return [r for r in (fn(event, db) for fn in RULES) if r]

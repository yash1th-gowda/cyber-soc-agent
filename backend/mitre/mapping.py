"""Deterministic rule -> ATT&CK mapping. The LLM never invents technique IDs."""
from __future__ import annotations

RULE_TO_TECHNIQUE = {
    "BRUTE_FORCE": ("T1110", "Brute Force"),
    "POSSIBLE_CREDENTIAL_COMPROMISE": ("T1078", "Valid Accounts"),
    "CREDENTIAL_DUMPING_TOOL": ("T1003", "OS Credential Dumping"),
    "SUSPICIOUS_POWERSHELL": ("T1059.001", "Command and Scripting Interpreter: PowerShell"),
    "PRIVILEGE_ESCALATION": ("T1098", "Account Manipulation"),
    "POSSIBLE_LATERAL_MOVEMENT": ("T1021", "Remote Services"),
    "SUSPICIOUS_EXTERNAL_CONNECTION": ("T1041", "Exfiltration Over C2 Channel"),
}
CONFIDENCE_STATUS_THRESHOLD = 0.75


def map_alert_to_mitre(alert: dict):
    entry = RULE_TO_TECHNIQUE.get(alert["rule"])
    if not entry:
        return None
    tid, name = entry
    return {"technique_id": tid, "technique_name": name, "confidence": alert["confidence"],
            "evidence": list(alert["evidence"]),
            "status": "detected" if alert["confidence"] >= CONFIDENCE_STATUS_THRESHOLD else "suspected",
            "source": "deterministic_mapping"}


def map_incident(alerts: list) -> list:
    by = {}
    for a in alerts:
        m = map_alert_to_mitre(a)
        if not m:
            continue
        ex = by.get(m["technique_id"])
        if not ex:
            by[m["technique_id"]] = m
        else:
            ex["evidence"] = sorted(set(ex["evidence"]) | set(m["evidence"]))
            if m["confidence"] > ex["confidence"]:
                ex["confidence"], ex["status"] = m["confidence"], m["status"]
    return list(by.values())

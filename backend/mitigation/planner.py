"""Deterministic rule -> recommendation mapping. Recommendations are never auto-executed."""
RULE_RECOMMENDATIONS = {
    "BRUTE_FORCE": [("Block or rate-limit source IP at the perimeter", "P2", "immediate"),
                    ("Review account lockout policy for targeted account(s)", "P3", "short_term")],
    "POSSIBLE_CREDENTIAL_COMPROMISE": [
        ("Temporarily disable the affected account pending verification", "P1", "immediate"),
        ("Force credential rotation for the affected account", "P2", "short_term"),
        ("Revoke active sessions for the affected account", "P1", "immediate")],
    "CREDENTIAL_DUMPING_TOOL": [
        ("Isolate the affected host from the network", "P1", "immediate"),
        ("Preserve forensic evidence (memory + disk) before remediation", "P1", "immediate"),
        ("Rotate credentials for all accounts with sessions on the affected host", "P1", "short_term")],
    "SUSPICIOUS_POWERSHELL": [
        ("Terminate the suspicious process if still running", "P2", "immediate"),
        ("Review PowerShell execution policy / enable constrained language mode", "P3", "short_term")],
    "PRIVILEGE_ESCALATION": [
        ("Review and, if unauthorized, revert the privileged group membership change", "P1", "immediate"),
        ("Audit recent privileged-group changes for the affected domain/host", "P2", "short_term")],
    "POSSIBLE_LATERAL_MOVEMENT": [
        ("Review authentication logs across all accessed hosts for the affected account", "P2", "immediate"),
        ("Consider network segmentation to limit further lateral movement", "P3", "short_term")],
    "SUSPICIOUS_EXTERNAL_CONNECTION": [
        ("Block the destination IP/domain at the firewall", "P1", "immediate"),
        ("Review outbound proxy logs for additional connections to the same destination", "P2", "short_term")],
}


def recommend_for_incident(incident: dict, alerts: list) -> list:
    seen, recs = set(), []
    for a in alerts:
        for action, prio, cat in RULE_RECOMMENDATIONS.get(a["rule"], []):
            if (action, a["rule"]) in seen:
                continue
            seen.add((action, a["rule"]))
            recs.append({"action": action, "priority": prio, "category": cat,
                         "reason": f"Triggered by rule {a['rule']} ({a['classification']}).",
                         "evidence": list(a["evidence"]), "requires_approval": True})
    recs.sort(key=lambda r: {"P1": 0, "P2": 1, "P3": 2}[r["priority"]])
    return recs

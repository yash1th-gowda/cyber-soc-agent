"""SIMULATION ONLY response engine. No code path here can touch a real network, host, firewall
or identity provider. execute_simulated() is reachable only via approve_action()."""
from __future__ import annotations

from datetime import datetime, timezone

from backend.models.schemas import ResponseAction

VALID_ACTION_TYPES = ("BLOCK_IP", "ISOLATE_HOST", "DISABLE_USER", "REVOKE_SESSION", "BLOCK_DOMAIN")
ACTION_FROM_RECOMMENDATION = {
    "Block or rate-limit source IP at the perimeter": "BLOCK_IP",
    "Temporarily disable the affected account pending verification": "DISABLE_USER",
    "Revoke active sessions for the affected account": "REVOKE_SESSION",
    "Isolate the affected host from the network": "ISOLATE_HOST",
    "Block the destination IP/domain at the firewall": "BLOCK_IP",
}


def _now():
    return datetime.now(timezone.utc).isoformat()


def propose_action_from_recommendation(rec: dict, incident: dict):
    action_type = ACTION_FROM_RECOMMENDATION.get(rec["action"])
    if not action_type:
        return None
    ents = incident.get("entities", {})

    if action_type in ("DISABLE_USER", "REVOKE_SESSION"):
        targets = ents.get("username", [])
    elif action_type == "ISOLATE_HOST":
        targets = ents.get("hostname", [])
    elif rec["action"] == "Block the destination IP/domain at the firewall":
        targets = ents.get("destination_ip", [])
    else:
        targets = ents.get("source_ip", [])

    # Fail safely if the incident doesn't identify a target.
    if not targets:
        return None

    target = ",".join(sorted(set(targets)))
    return ResponseAction(action_type=action_type, target=target,
                          incident_id=incident["incident_id"], reason=rec["reason"]).to_dict()


def approve_action(action: dict, approved_by: str) -> dict:
    if action["status"] != "pending_approval":
        raise ValueError(f"Action {action['action_id']} is not pending approval (status={action['status']})")
    action["status"], action["approved_by"], action["decided_at"] = "approved", approved_by, _now()
    return execute_simulated(action)


def reject_action(action: dict, rejected_by: str) -> dict:
    if action["status"] != "pending_approval":
        raise ValueError(f"Action {action['action_id']} is not pending approval (status={action['status']})")
    action["status"], action["approved_by"], action["decided_at"] = "rejected", rejected_by, _now()
    action["result"] = "Action rejected by analyst; no simulation performed."
    return action


def execute_simulated(action: dict) -> dict:
    if action["status"] != "approved":
        raise ValueError("Only approved actions may be simulated.")
    t, tgt = action["action_type"], action["target"]
    msgs = {
        "BLOCK_IP": f"SIMULATED: firewall block rule applied for {tgt}. No real network modification performed.",
        "ISOLATE_HOST": f"SIMULATED: network isolation flag applied to host(s) {tgt}. No real network modification performed.",
        "DISABLE_USER": f"SIMULATED: account(s) {tgt} flagged as disabled. No real identity-provider change performed.",
        "REVOKE_SESSION": f"SIMULATED: session(s) for {tgt} flagged as revoked. No real session was terminated.",
        "BLOCK_DOMAIN": f"SIMULATED: DNS/firewall block applied for {tgt}. No real network modification performed."}
    action["status"] = "simulated"
    action["result"] = msgs.get(t, f"SIMULATED action {t} on {tgt}.")
    return action

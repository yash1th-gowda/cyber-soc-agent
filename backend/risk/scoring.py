"""Deterministic 0-100 risk score:
40*severity_weight + 25*confidence + 15*min(events/10,1) + 10*min(entities/5,1) + 10*min(confirmed_mitre/3,1)"""
SEVERITY_WEIGHT = {"informational": 0.0, "low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}


def _terms(inc: dict) -> dict:
    sw = SEVERITY_WEIGHT.get(inc["severity"], 0.5)
    n_events = len(inc.get("event_ids", []))
    n_ents = sum(len(v) for v in inc.get("entities", {}).values())
    mitre = inc.get("mitre_techniques", [])
    confirmed = [m for m in mitre if m.get("status") == "confirmed"]
    return {"severity_term": 40 * sw, "confidence_term": 25 * inc["confidence"],
            "event_volume_term": 15 * min(n_events / 10, 1.0),
            "entity_spread_term": 10 * min(n_ents / 5, 1.0),
            "mitre_confirmation_term": 10 * (min(len(confirmed) / 3, 1.0) if mitre else 0.0),
            "inputs": {"severity": inc["severity"], "confidence": inc["confidence"],
                       "correlated_event_count": n_events, "distinct_entity_count": n_ents,
                       "mitre_confirmed_count": len(confirmed)}}


def compute_risk_score(inc: dict) -> int:
    t = _terms(inc)
    total = sum(t[k] for k in t if k.endswith("_term"))
    return max(0, min(100, round(total)))


def explain_risk_score(inc: dict) -> dict:
    t = _terms(inc)
    out = {k: round(v, 1) for k, v in t.items() if k.endswith("_term")}
    out["total"] = compute_risk_score(inc)
    out["inputs"] = t["inputs"]
    return out

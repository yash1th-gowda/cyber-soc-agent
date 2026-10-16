"""Orchestration: ingest -> detect -> correlate -> incident -> MITRE -> risk -> investigation -> mitigation."""
from __future__ import annotations

from backend.anomaly.detector import AnomalyDetector
from backend.correlation.engine import build_incident_from_cluster, correlate
from backend.detection.rules import evaluate_event
from backend.investigation.agent import InvestigationAgent
from backend.mitigation.planner import recommend_for_incident
from backend.mitre.mapping import map_incident
from backend.models.schemas import Alert, Incident, SecurityEvent, ValidationError
from backend.risk.scoring import compute_risk_score

_IDENTITY_FIELDS = ("event_id", "timestamp", "source", "event_type", "severity", "source_ip",
                    "destination_ip", "username", "hostname", "process", "command",
                    "bytes_transferred", "message")


class Pipeline:
    def __init__(self, db, investigation_agent: InvestigationAgent | None = None):
        self.db = db
        self.investigation_agent = investigation_agent or InvestigationAgent()
        self.anomaly_detector = AnomalyDetector()

    def ingest_event(self, raw_event: dict) -> dict:
        event = SecurityEvent.from_dict(raw_event)
        existing = self.db.get_event(event.event_id)
        if existing is not None:
            new = event.to_dict()
            if all(existing.get(f) == new.get(f) for f in _IDENTITY_FIELDS):
                self.db.audit("system", "ingest_event_duplicate_identical", target=event.event_id, result="no_op")
                return {"event": existing, "alerts": [], "duplicate": "identical"}
            self.db.audit("system", "ingest_event_duplicate_conflict", target=event.event_id, result="rejected")
            raise ValidationError(f"event_id '{event.event_id}' already exists with different content; "
                                  "event IDs must be unique and immutable.")
        self.db.insert_event(event.to_dict())
        self.db.audit("system", "ingest_event", target=event.event_id, result="success")
        fired = []
        for ad in evaluate_event(event.to_dict(), self.db):
            alert = Alert(**ad)
            self.db.insert_alert(alert.to_dict())
            self.db.audit("system", "alert_fired", target=alert.alert_id, result="success",
                          details={"rule": alert.rule})
            fired.append(alert.to_dict())
        return {"event": event.to_dict(), "alerts": fired}

    def run_correlation(self) -> list:
        open_alerts = self.db.unassigned_alerts()
        if not open_alerts:
            return []
        out = []
        for cluster in correlate(open_alerts, self.db):
            inc = Incident(**build_incident_from_cluster(cluster, self.db)).to_dict()
            inc = self._enrich(inc, cluster)
            self.db.insert_incident(inc)
            for a in cluster:
                self.db.set_alert_incident(a["alert_id"], inc["incident_id"])
            self.db.audit("system", "incident_created", target=inc["incident_id"], result="success",
                          details={"severity": inc["severity"]})
            out.append(inc)
        return out

    def _enrich(self, inc: dict, cluster: list) -> dict:
        inc["mitre_techniques"] = map_incident(cluster)
        inc["risk_score"] = compute_risk_score(inc)
        inc["investigation"] = self.investigation_agent.investigate(inc, cluster)
        inc["recommendations"] = recommend_for_incident(inc, cluster)
        inc["status"] = "investigating"
        return inc

    def run_full_pipeline(self, events: list) -> dict:
        res = {"ingested": 0, "alerts": 0, "errors": []}
        for raw in events:
            try:
                r = self.ingest_event(raw)
                res["ingested"] += 1
                res["alerts"] += len(r["alerts"])
            except ValidationError as e:
                res["errors"].append({"event": raw.get("event_id") if isinstance(raw, dict) else None,
                                      "error": str(e)})
        res["incidents"] = self.run_correlation()
        return res

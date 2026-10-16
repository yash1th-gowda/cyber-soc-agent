"""Canonical data models (validated dataclasses; Pydantic-equivalent checks).
Dataclasses used because the build sandbox had no network to install pydantic."""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

# Identifier shape restriction: second layer of XSS defense (dashboard esc() is primary).
_SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9._\-:]{1,128}$")

SEVERITIES = ("informational", "low", "medium", "high", "critical")
ALERT_STATUSES = ("open", "investigating", "resolved", "false_positive")
INCIDENT_STATUSES = ("new", "investigating", "contained", "resolved", "false_positive")
MITRE_STATUSES = ("detected", "suspected", "confirmed", "unknown")


class ValidationError(Exception):
    pass


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise ValidationError(msg)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class SecurityEvent:
    event_id: str
    timestamp: str
    source: str
    event_type: str
    severity: str = "informational"
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    process: Optional[str] = None
    command: Optional[str] = None
    bytes_transferred: Optional[int] = None
    message: str = ""
    raw_event: dict = field(default_factory=dict)
    indicators: list = field(default_factory=list)

    def __post_init__(self):
        _require(bool(self.event_id), "event_id is required")
        _require(isinstance(self.event_id, str) and bool(_SAFE_IDENTIFIER_RE.match(self.event_id)),
                 "event_id must be 1-128 chars of letters, digits, '.', '_', '-', ':' only "
                 f"(got: {self.event_id!r})")
        _require(bool(self.timestamp), "timestamp is required")
        _require(bool(self.source), "source is required")
        _require(bool(self.event_type), "event_type is required")
        _require(self.severity in SEVERITIES, f"invalid severity: {self.severity}")
        try:
            datetime.fromisoformat(str(self.timestamp).replace("Z", "+00:00"))
        except Exception as e:
            raise ValidationError(f"timestamp is not valid ISO-8601: {self.timestamp}") from e

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict) -> "SecurityEvent":
        """Tolerates unknown fields (kept under raw_event._unrecognized_fields)
        instead of crashing with a raw TypeError."""
        if not isinstance(raw, dict):
            raise ValidationError(f"event payload must be a JSON object, got {type(raw).__name__}")
        known = set(cls.__dataclass_fields__)
        extra = {k: v for k, v in raw.items() if k not in known}
        clean = {k: v for k, v in raw.items() if k in known}
        if extra:
            rr = dict(clean.get("raw_event") or {})
            rr["_unrecognized_fields"] = extra
            clean["raw_event"] = rr
        return cls(**clean)


@dataclass
class Alert:
    rule: str
    classification: str
    severity: str
    confidence: float
    event_ids: list
    evidence: list
    alert_id: str = field(default_factory=lambda: f"ALT-{uuid.uuid4().hex[:8].upper()}")
    reasoning: list = field(default_factory=list)
    indicators: list = field(default_factory=list)
    status: str = "open"
    created_at: str = field(default_factory=_now)

    def __post_init__(self):
        _require(self.severity in SEVERITIES, f"invalid severity: {self.severity}")
        _require(0.0 <= self.confidence <= 1.0, "confidence must be in [0,1]")
        _require(len(self.event_ids) > 0, "alert must reference at least one event_id")
        _require(self.status in ALERT_STATUSES, f"invalid status: {self.status}")

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ResponseAction:
    action_type: str
    target: str
    incident_id: str
    reason: str
    action_id: str = field(default_factory=lambda: f"ACT-{uuid.uuid4().hex[:8].upper()}")
    status: str = "pending_approval"
    approved_by: Optional[str] = None
    result: Optional[str] = None
    created_at: str = field(default_factory=_now)
    decided_at: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Incident:
    title: str
    severity: str
    confidence: float
    incident_id: str = field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:6].upper()}")
    status: str = "new"
    event_ids: list = field(default_factory=list)
    alert_ids: list = field(default_factory=list)
    entities: dict = field(default_factory=dict)
    timeline: list = field(default_factory=list)
    attack_chain: list = field(default_factory=list)
    mitre_techniques: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    risk_score: Optional[int] = None
    investigation: Optional[dict] = None
    recommendations: list = field(default_factory=list)
    response_actions: list = field(default_factory=list)
    created_at: str = field(default_factory=_now)

    def __post_init__(self):
        _require(self.severity in SEVERITIES, f"invalid severity: {self.severity}")
        _require(0.0 <= self.confidence <= 1.0, "confidence must be in [0,1]")
        _require(self.status in INCIDENT_STATUSES, f"invalid status: {self.status}")

    def to_dict(self) -> dict:
        return asdict(self)

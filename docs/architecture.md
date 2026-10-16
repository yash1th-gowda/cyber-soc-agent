# Architecture

Modular monolith: `frontend/dashboard.html` -> Flask API (`backend/api/app.py`) -> `Pipeline` (`backend/pipeline.py`)
-> deterministic modules -> SQLite. No queues, no services, no network hops between components.

## Flow
1. **Validate** (`models/schemas.py`): `SecurityEvent.from_dict` - required fields, severity enum, ISO timestamp,
   identifier charset for `event_id`; unknown fields preserved under `raw_event._unrecognized_fields`.
2. **Integrity**: existing `event_id` + identical content -> idempotent no-op (no re-detection); different content -> rejected (409).
3. **Detect** (`detection/rules.py`): 7 rules `(event, db) -> alert | None`. Alerts list the evidence event IDs and reasoning.
   Window rules (`BRUTE_FORCE`, `POSSIBLE_LATERAL_MOVEMENT`, `POSSIBLE_CREDENTIAL_COMPROMISE`) use a **symmetric** time window
   (`events_in_symmetric_window`) so ingestion order does not matter, plus an evidence-overlap dedup so a burst fires once.
   `SUSPICIOUS_EXTERNAL_CONNECTION` is intentionally backward-looking (a connection *following* PowerShell).
4. **Correlate** (`correlation/engine.py`): union-find over "alerts share source_ip/username/hostname AND their earliest
   evidence-event timestamps are within 15 minutes". Single alerts still become incidents.
5. **Enrich**: timeline from real event timestamps; attack chain from a fixed rule ordering; MITRE from a static 7-row table
   (status `confirmed` if alert confidence >= 0.75 else `suspected`); risk score formula below.
6. **Investigate** (`investigation/`): one agent -> `LLMProvider`. `MockProvider` is extractive: each field is a formatting of
   structured data already in the incident, so it cannot invent events, IPs, techniques, or claim execution.
7. **Recommend** (`mitigation/planner.py`): static rule -> action table; all `requires_approval: true`.
8. **Respond** (`response/simulator.py`): propose (`pending_approval`) -> human approve/reject -> `execute_simulated` only from `approved`.
9. **Report** (`reporting/`) and **audit** (`audit_log` table) for every system and human action.

## Anomaly signal
`anomaly/detector.py` (IsolationForest over per-user counts). Output vocabulary is only `normal`/`anomalous`, flagged
`demo_mode` below 12 entities. It is **not** wired to override or create detections; it is a separate, explicitly secondary signal.

## Risk score (deterministic, 0-100)
`40*severity_weight + 25*confidence + 15*min(events/10,1) + 10*min(entities/5,1) + 10*min(confirmed_mitre/3,1)`
with severity weights informational 0, low .25, medium .5, high .75, critical 1. `GET /incidents/{id}/risk` returns every term.

## Deviations
Flask + sqlite3 + dataclasses instead of FastAPI + PostgreSQL + Pydantic (sandbox without network). Routes and schemas mirror the
intended contracts so a port is mechanical.

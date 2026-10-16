# Engineering Report (hardening phase)

## Provenance - read this first
The hardening pass was performed on the originally built code (baseline recorded then: 43 tests, 43 passed, 0 failed, ~0.45 s).
Between turns the sandbox was **reset and the working directory was lost** (the project had not yet been copied to outputs).
The project was **rebuilt from the conversation record with every hardening fix included**, then re-verified from scratch.
All results below are from the rebuilt code in this repository; the 43-test baseline is historical and not reproducible here.
The rebuild also tightened a few things (see D). Nothing in this report is carried over unverified.

## A. Summary of changes (vs. the original build)
Correctness: out-of-order ingestion fix; duplicate-ID integrity; unknown-field tolerance; correlation window on event time;
timezone-aware timestamps. Security: dashboard escaping, identifier validation, no stack-trace leakage, debug off, localhost bind,
input clamping. Tests: 82 (from 43). Docs rewritten to match code.

## B. Defects found and fixed
| # | Defect (reproduced before fixing) | Fix | Regression test |
|---|---|---|---|
| 1 | 5 failed logins ingested out of order produced **0 alerts** (backward-only window) | symmetric window + evidence-overlap dedup | `TestOutOfOrderIngestion` (4 tests) |
| 2 | Duplicate `event_id` silently overwrote stored evidence | identical = no-op, conflict = 409 | `TestDuplicates`, `test_duplicate_conflict_409` |
| 3 | One unknown field crashed ingestion with raw `TypeError` | `from_dict` preserves extras | `test_unknown_field_tolerated_and_preserved` |
| 4 | Dashboard inserted event-derived text via unescaped `innerHTML` (XSS) | `esc()` everywhere; inline handlers removed | `TestFrontendEscaping` (static) |
| 5 | `event_id` accepted HTML-shaped values | charset restriction | `test_html_shaped_event_id_rejected` |
| 6 | Flask `debug=True` default (stack-trace/RCE-console exposure) | off by default, opt-in env var, 127.0.0.1 bind, JSON error handlers | `test_unhandled_exception_returns_clean_500` |
| 7 | In-memory DB connections shared across instances (cross-test leakage) | connection per instance | whole-suite run |
| 8 | **Found during final docs review:** correlation 15-min window used alert *creation* wall-clock time, so historical events always merged | use earliest evidence-event timestamp | `test_same_entity_but_events_hours_apart_do_not_merge` |
| 9 | Deprecated `datetime.utcnow()` | timezone-aware | suite run with `-W error::DeprecationWarning` |

## C. Feature verification
| Feature | Status | Evidence |
|---|---|---|
| Ingestion + validation | Verified | unit + API tests |
| 7 detection rules | Verified | per-rule positive/negative tests, scenario runs |
| Correlation / incident / timeline / attack chain | Verified | correlation tests, primary scenario test (timeline sorted, chain exact) |
| MITRE mapping (confirmed/suspected, evidence) | Verified | `test_mitre_mapping.py`, scenario test |
| Risk score | Verified | bounds + determinism test; breakdown endpoint in live run |
| Mock investigation (grounded, uncertainty, no execution claims) | Verified | `TestPromptInjection` |
| Mitigation -> approval -> simulation -> audit -> report | Verified | API tests + live HTTP run |
| Persistence across restart | Verified | live server restart; `test_persistence_across_reopen` |
| Anomaly signal | Verified as a demo-mode secondary signal only | `test_anomaly.py` |
| Dashboard rendering in a browser | **Not verified** | no browser/JS runner available; static checks only |
| OpenAI provider | **Not implemented/not tested** | fails closed |

## D. Notes on the rebuild
Added during rebuild: buttons use event listeners instead of inline `onclick`; `limit` clamping; `approved_by` length cap; dashboard
shows critical/high count and recent activity; extra tests (correlation scenarios, API 404/400 matrix, reject flow, prompt-injection payload set).

## E. Test results (measured)
`Ran 82 tests, OK`: 61 unit + 21 integration; 0 failed, 0 errors, 0 skipped; ~1.0 s (warnings-as-errors).

## F. Demo results
See table in `docs/evaluation.md` - all six scenarios match documented expectations. Live HTTP run: upload -> 9 events, 5 alerts, 1 critical
incident (risk 92); proposal left `response_actions` empty until approval; approval produced `simulated` with an explicit "No real ... change performed"
message; second approval returned 409; report contained SIMULATED labelling; after server restart the incident and the approved simulated action persisted.
A generated report is saved as `docs/sample_incident_report.md`.

## G. Known limitations
No auth/RBAC; no rate limiting; six synthetic scenarios only (no real-world accuracy claim); anomaly detector always in demo mode here; mean-confidence
aggregation can understate multi-stage incidents; credential-compromise success-before-failures gap; shared source IP merges unrelated users' alerts (documented by test);
dashboard not browser-tested; SQLite demo scale.

## H. Optional features
Not implemented **by design/scope**: RBAC/auth, RAG, attack graph, WebSocket feed, richer anomaly features.
Not implemented **due to environment**: FastAPI/PostgreSQL/Pydantic (no network), live LLM provider (no network/key), browser-level UI tests.

## I. Architecture status
Flask + sqlite3 remain because the build environment could not install FastAPI/SQLAlchemy/Pydantic; the deviation from the original preference is deliberate and documented. Migration is future work.

## J. Recommendation
**READY FOR DEMO** (local, single user, trusted network). **Not yet ready for academic submission as a validated detector**: acceptable only if presented as
a design/integration project with the stated synthetic-data limitation and the no-auth gap disclosed; the UI should be exercised once in a real browser first.

# Evaluation

All numbers come from running this repository (`python3 -m unittest discover -s tests -p "test_*.py"`, `scripts/replay.py --all`,
and a live HTTP run). **The evaluation uses six synthetic scenarios and does not represent general real-world detection accuracy.**
The scenarios were written by the developers, each sitting clearly on one side of the rule thresholds.

## Test suite (measured)
`Ran 82 tests ... OK` (61 unit + 21 integration; 0 failures, 0 errors, 0 skipped; ~1 s), run with deprecation warnings as errors.
Coverage: every detection rule (positive/negative), out-of-order and burst-dedup regressions, duplicate-ID handling, malformed input,
correlation (should/should-not group, time window, benign mixed in), MITRE mapping, risk bounds/determinism, response safety
(no execution without approval, no real-execution primitives in source, double-decision fails closed), prompt-injection payloads,
API validation/404/409/400/500 behaviour, dashboard escaping (static), full-scenario pipeline, persistence on reopen.

## Scenario results (measured)
| Scenario | Expected | Actual | Status |
|---|---|---|---|
| brute_force | BRUTE_FORCE, 1 incident, T1110 | 1 alert, 1 incident, high, risk 68, T1110 | match |
| credential_compromise | 1 correlated critical incident; T1078,T1059.001,T1098,T1041 | 5 alerts -> 1 incident, critical, risk 92, conf 0.84, all four `confirmed` | match |
| suspicious_powershell | SUSPICIOUS_POWERSHELL only | 1 alert, high, risk 58, T1059.001 | match |
| privilege_escalation | PRIVILEGE_ESCALATION only | 1 alert, high, risk 59, T1098 | match |
| lateral_movement | POSSIBLE_LATERAL_MOVEMENT | 1 alert, high, risk 64, T1021 | match |
| benign_admin_activity | zero alerts | 0 alerts, 0 incidents | match |

Scenario-level confusion matrix (label = "should produce an incident"): TP 5, TN 1, FP 0, FN 0. Precision/recall/F1 = 1.0 **on these six
hand-built cases only**; with n=6 this is a behavioural check, not an accuracy estimate.
Correlation: grouping and separation checks pass (multi-stage merges; unrelated bursts stay separate; same entity hours apart stays separate).
Not measured: anomaly-detector ROC/PR (no labeled multi-entity data; every scenario has 1 entity -> `demo_mode`), hallucination rate of a real LLM
(none was run), throughput/latency. What data would be needed: a labeled, multi-entity telemetry corpus with benign baselines.

## AI investigation checks (what was actually verified)
The mock provider is extractive: tests confirm outputs contain the required fields, cite evidence IDs, state alternative explanations and
missing evidence, never claim executed actions, and are unchanged by injected instructions in `command`/`message`/`username`. No claim is made
about LLM-provider quality.

## Baselines
Only the combined system was built; comparisons to rules-only/ML-only/LLM-only are descriptive, not measured.

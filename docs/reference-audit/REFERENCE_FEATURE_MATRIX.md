# REFERENCE_FEATURE_MATRIX.md — CYBER-SOC AGENT

`CyberSocial-main` is excluded (unrelated social-forum project). Legend: ✅ present & solid · ⚠️ present but weak/partial · ❌ absent.

| Feature | Agentic-Cybersecurity-Soc | CyberSOC v1 (OpenEnv) | CyberSOC v2 (OpenEnv) | cyber-soc-agent | cyber_soc | cyberdev-soc | jjnet-security-agents | **Verdict for our build** |
|---|---|---|---|---|---|---|---|---|
| Log/event ingestion | ⚠️ (one JSON in, no adapters) | ⚠️ (simulated observations) | ⚠️ (simulated observations) | ❌ (stub only) | ⚠️ (synthetic generator) | ⚠️ (single sample file) | ✅ (Palo Alto/Cortex XDR log parsing) | **REPLACE** — build real multi-source adapters (Sec. 35) |
| Alert ingestion | ✅ (classifies incoming events) | ✅ (typed `Alert`) | ✅ (typed `current_alert`) | ❌ | ⚠️ | ❌ | ✅ | **MODIFY** — combine typed schema (v1/v2) + Agentic's classification rules |
| Log triage | ✅ (rule-based, 7 categories) | ✅ (as a game action) | ✅ (Task 1) | ❌ | ⚠️ (simple) | ✅ (LLM-based, typed output) | ✅ (stage 1 of 8) | **KEEP** — merge Agentic's deterministic rules with cyberdev's typed LLM output |
| Anomaly detection | ✅ (9 real detections, threshold-based) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | **KEEP & EXTEND** — only real anomaly logic in the set; add a real ML model (Isolation Forest) on top |
| Event correlation | ✅ (kill-chain staging) | ⚠️ (node/graph state, not full correlation) | ⚠️ | ❌ | ❌ | ❌ | ⚠️ (implicit in datapack) | **KEEP & EXTEND** — build explicit multi-key correlation engine (Sec. 11), none of the repos has one |
| Attack-chain reconstruction | ✅ (timeline + narrative) | ❌ | ⚠️ (Task 3 only) | ❌ | ❌ | ⚠️ (timeline field) | ✅ (attack-chain parsing in Consultant agent) | **MODIFY** — combine Agentic's timeline builder + jjnet's chain parsing |
| MITRE ATT&CK mapping | ✅ (deterministic, 11 stages) | ❌ | ❌ | ❌ | ❌ | ✅ (LLM field, no confidence/evidence split) | ✅ (tactic+technique matrix) | **KEEP** — Agentic's deterministic base + evidence/confidence fields per Sec. 13 |
| Threat intelligence | ❌ | ❌ | ⚠️ (`check_reputation` action) | ⚠️ (stub endpoint) | ❌ | ✅ (`tools/vulnerability.py`, CVE context) | ❌ | **REPLACE** — build real IOC/CVE lookup with offline fixtures (Sec. 14) |
| Vulnerability context | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | **MODIFY** — extend cyberdev's `vulnerability.py` concept |
| Incident investigation (AI) | ❌ (no LLM at all) | ⚠️ (RL policy, not analyst-style) | ⚠️ | ❌ | ❌ | ✅ (dedicated Investigation Agent) | ✅ (8-stage workflow) | **REPLACE** — new evidence-grounded investigation agent (Sec. 16–18), using jjnet's structure as template |
| RAG | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (training-material RAG, Task 4) | **BUILD NEW** — none targets security-knowledge RAG; adapt jjnet's chunk→index→retrieve pipeline shape |
| Memory | ❌ | ⚠️ (episode state only) | ⚠️ | ❌ | ⚠️ (in-process dict) | ❌ | ⚠️ (implicit via datapack files) | **BUILD NEW** — no repo has structured short/long-term memory (Sec. 19) |
| Mitigation planning | ✅ (P1/P2/P3 + Sigma rules) | ⚠️ (action selection, cost-scored) | ⚠️ | ❌ | ❌ | ⚠️ (`tools/response.py`, no priority tiers) | ✅ (4-phase playbook, 0–2h/2–8h/24h/72h) | **KEEP** — merge Agentic's P1/P2/P3 tiers + jjnet's time-phased playbook |
| Response execution | ❌ | ✅ (typed actions, but *simulated within the RL env*) | ✅ (typed actions, simulated) | ⚠️ (stub) | ❌ | ⚠️ (`tools/response.py`, unclear gating) | ❌ (report-only, no execution) | **BUILD NEW** — simulation-only engine w/ required schema fields (borrow v1/v2 typed-action pattern), hard human-approval gate (Sec. 21–23) |
| Reporting | ✅ (Markdown) | ❌ | ❌ | ❌ | ❌ | ✅ (JSON) | ✅ (11-section Word/PDF/MD/Email, best in class) | **ADOPT** — jjnet's 11-section structure as our report template |
| Evaluation / grading | ⚠️ (68 pytest tests, functional not accuracy-based) | ✅ (deterministic graders, reward shaping) | ✅ (per-scenario grader package) | ❌ | ❌ | ❌ | ❌ | **ADOPT** — v1/v2's grader-per-scenario pattern for Sec. 46–48 |
| Dashboard / UI | ❌ (CLI only) | ✅ (debug dashboard) | ⚠️ (API only, "browser dashboard" mentioned) | ❌ | ✅ (live WebSocket feed, vanilla JS) | ❌ | ✅ (full SPA, `app.js` 97KB) | **BUILD NEW** — proper SOC UI per Sec. 25–27; reuse cyber_soc's WebSocket push pattern for the live feed |
| Authentication / RBAC | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ⚠️ (implied "supervisor sign-off" role, not real auth) | **BUILD NEW** — no repo has real RBAC (Sec. 39) |
| Audit logging | ❌ | ⚠️ (trajectory log, for RL not compliance) | ⚠️ | ❌ | ❌ | ❌ | ⚠️ (revision-history section in report) | **BUILD NEW** — no repo has a real audit-log table (Sec. 40) |
| Testing | ✅ (68 tests claimed) | ✅ (graders act as tests) | ✅ (graders act as tests) | ❌ | ❌ | ❌ | ❌ (no visible test suite) | **BUILD NEW / ADOPT pattern** — combine Agentic's pytest habit with v1/v2's grader pattern |
| Human approval gate | ❌ | ⚠️ (implicit via action cost, not an approval workflow) | ⚠️ | ❌ | ❌ | ❌ | ⚠️ (supervisor sign-off exists only in the *training* module, not incident response) | **BUILD NEW** — nothing implements Sec. 22 as specified; must design fresh |
| Prompt-injection defense | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | **BUILD NEW** — genuine gap across all 7 relevant repos (Sec. 43) |
| Evidence-grounded / anti-hallucination discipline | ⚠️ (implicit — rules ARE the evidence) | N/A | N/A | ❌ | ❌ | ❌ | ✅ (explicit "Low confidence, don't fabricate, list missing evidence" rule) | **ADOPT** — jjnet's explicit discipline is the model to formalize into our QC agent (Sec. 29) |

---

## Net Conclusion

No single repository is close to the target. The **detection/correlation backbone should be built from scratch using Agentic-Cybersecurity-Soc-main's rule logic as a seed**, the **investigation-agent I/O contracts should follow cyberdev-soc's typed-output convention**, the **report structure and evidence discipline should follow jjnet's template**, and the **evaluation harness should adopt the grader-per-scenario pattern from both CyberSOC OpenEnv repos**. Everything else in the target architecture — persistent incident state, RAG, memory, human-approval gating, RBAC, audit logging, attack-graph UI, prompt-injection defense — has to be designed and built new; it does not exist in usable form in any reference repo.

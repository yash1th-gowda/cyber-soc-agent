# REFERENCE_AUDIT.md — CYBER-SOC AGENT

Audit of the 8 uploaded repositories. Each was unzipped and read directly (READMEs, entry points, agent code, schemas) rather than assumed from filenames.

---

## 1. `Agentic-Cybersecurity-Soc-main`
**~4,100 LOC, pure Python, no LLM calls**

- **Purpose**: A deterministic, rule-based 6-agent pipeline (Triage → Anomaly → Correlation → Mitigation → Report → Orchestrator).
- **Architecture**: Strict sequential pipeline, each agent is a plain Python class with hand-coded rules (regex/keyword matching) for classification.
- **AI/ML**: None. "Agent" here means "pipeline stage," not an LLM-driven agent. No embeddings, no model calls.
- **Security logic**: Genuinely useful — hard-coded detections for brute force, password spraying, impossible travel, suspicious PowerShell (`IEX`, `-EncodedCommand`), beaconing (regularity-based), cloud IAM abuse (`CreateAccessKey`, `AttachUserPolicy`), credential dumping (mimikatz/lsass/procdump), lateral movement (WMI/PsExec/pass-the-hash).
- **MITRE**: Maps to 11 ATT&CK kill-chain stages with deduplicated technique IDs — deterministic, not LLM-guessed.
- **Reporting**: Generates Markdown incident reports (exec summary, IOCs, RCA).
- **Testing**: Claims a 68-test pytest suite — real signal that this is closer to "engineered" than the smaller repos.
- **Weakness**: No real ingestion pipeline, no persistence, no web UI, no threat intel, no RAG, no human-approval gate, no real anomaly *model* (all thresholds/regex).
- **Verdict: ADOPT the anomaly-detection rule logic and the kill-chain/MITRE mapping approach as the deterministic backbone.** This is the strongest "detection engine" reference of the set.

---

## 2. `CyberSOC-main` (v1 — HF Space / OpenEnv submission)
**~4,000 LOC + a 750KB SFT training JSONL**

- **Purpose**: Not a SOC product — it's an **OpenEnv RL training environment** ("Autonomous CyberSOC OpenEnv++") built for a Hugging Face hackathon. The "SOC" is a simulated game: `reset()/step()/state()`, typed `Action`/`Observation`/`Reward`, three difficulty tasks (`alert-triage-easy`, `incident-containment-medium`, `soc-optimization-hard`).
- **Architecture**: FastAPI service exposing an RL-gym-style API; agent picks from 8 actions (`triage_alert`, `isolate_node`, `patch_system`, `block_indicator`, `request_forensics`, `escalate_incident`, `ignore_alert`, `noop`); deterministic graders score trajectories in `(0,1)`.
- **AI/ML**: Includes a TRL/SFT fine-tuning pipeline and training-loss plots — this is model-training infrastructure, not investigation infrastructure.
- **Useful idea**: The **action-cost/trade-off reward model** (damage vs. response cost vs. delay) is a genuinely good mental model for scoring mitigation recommendations, and the **typed action schema with required fields per action** (e.g. `isolate_node` requires `node_id`) is a clean pattern for our response-action schema.
- **Weakness**: No dashboard for humans, no incident data model resembling a real SOC, no MITRE mapping, no RAG, no reporting. It solves a different problem (agent benchmarking, not analyst tooling).
- **Verdict: DO NOT adopt architecture. Borrow only: typed action schemas, and the idea of a scored/gated action space.**

---

## 3. `CyberSOC-main` (v2 — different repo, same name)
**~2,500 LOC**

- **Purpose**: Another OpenEnv-style RL environment, independently built, covering phishing triage / malware investigation / multi-vector incident response as three difficulty tiers.
- **Architecture**: `CyberSOCObservation`/`CyberSOCAction` Pydantic models; action types `query_logs|check_reputation|isolate_host|collect_forensics|escalate|conclude`; includes a `confidence` field on every action and a graders package (`incident_grader.py`, `malware_grader.py`, `phishing_grader.py`).
- **Useful idea**: The **grader package structure** (one grader file per scenario type, each scoring against an expected outcome) is directly reusable for our own evaluation harness (Section 46–48 of the brief).
- **Weakness**: Same category as v1 — a training/eval environment, not an operational platform. No persistence, no UI, no real investigation agent.
- **Verdict: DO NOT adopt as architecture. Borrow the grader-per-scenario pattern for `tests/evaluation/`.**

---

## 4. `CyberSocial-main`
**~6,300 LOC, Chinese-language README, FastAPI + SQLite + SQLAlchemy + Jinja2 + HTMX**

- **Purpose**: This is **not a cybersecurity project**. It's a local-first social-forum demo for AI agents ("a Weibo-style forum for AI agents") — communities, posts, comments, agent profiles, likes, an admin console, a "runtime" behavior layer.
- **Relevance to CYBER-SOC AGENT: none.** It appears to have been included by mistake or bundled from an unrelated prior project.
- **Verdict: DO NOT USE. Excluded from the feature matrix below.**

---

## 5. `cyber-soc-agent-main`
**~240 LOC — smallest repo, multi-language (Go + Python)**

- **Purpose**: A skeleton, not a working system. Three FastAPI stub endpoints (`/threat-intel`, `/policy-check`, `/incident-response`) each calling a ~20-line placeholder function; a separate Go `ingestion/main.go` stub; an `orchestration/workflow.json` describing an intended workflow shape that was never implemented.
- **Empty README.**
- **Weakness**: No real logic anywhere — every "agent" function is a few lines returning a hardcoded dict. No tests, no persistence, no correlation, no MITRE, no UI.
- **Useful idea**: The `orchestration/payload_schema.json` and `workflow.json` sketch a workflow-engine shape (named steps with input/output contracts) worth glancing at, but it's too thin to be load-bearing.
- **Verdict: DO NOT USE beyond a two-minute glance at the workflow JSON shape.**

---

## 6. `cyber_soc-main`
**~530 LOC — FastAPI + WebSocket + vanilla JS frontend**

- **Purpose**: A minimal live-updating demo: a background task fakes a stream of security logs (`log_generator.py`), an `agent.py` classifies each one, results are broadcast to a browser over a WebSocket, rendered by plain `app.js`/`index.html`/`styles.css`.
- **Architecture**: Single-process, in-memory `asyncio.Queue`, no database (a `memory.py` module is just an in-process store, not persistent).
- **Useful idea**: The **live WebSocket log→classification→UI push loop** is a nice UX pattern worth reusing for our dashboard's "live alert feed," even though the underlying classification logic itself is trivial.
- **Weakness**: No persistence, no real correlation/incident model, no auth, no MITRE, no RAG, no human approval.
- **Verdict: MODIFY-and-reuse the WebSocket streaming pattern only.**

---

## 7. `cyberdev-soc-main`
**~510 LOC — Python, uses `pydantic-ai`-style agents (`agents.py`, `chain.py`, `tools/`)**

- **Purpose**: A 3-agent LLM chain (Triage → Investigation → Report), each a typed `pydantic-ai` agent with structured output classes, plus a `tools/` package (`attck.py`, `context.py`, `investigation.py`, `response.py`, `vulnerability.py`) registered as callable tools.
- **Architecture**: `main.py` loads one `sample_alert.json`, runs `chain.py`'s `run_incident_chain()`, which sequentially awaits three agent calls, threading prior output into the next prompt as an f-string.
- **Useful idea**: The **typed structured-output-per-agent pattern** (`triage.severity`, `triage.is_true_positive`, `investigation.mitre_technique`, `investigation.blast_radius`) is exactly the "structured objects, not raw strings between agents" principle the brief calls for — this is the best example of that principle in the reference set, even though it's small.
- **Weakness**: This is precisely the "five independent LLM calls passing text forward" anti-pattern the brief explicitly warns against (Section 6) — no deterministic anomaly detection, no evidence-grounding enforcement, no correlation engine, no persistence, no UI, no human approval, no offline/mock mode shown in the entry point.
- **Verdict: ADOPT the typed-agent-output pattern as a coding convention. DO NOT adopt the "3 sequential LLM calls = whole system" architecture.**

---

## 8. `jjnet-security-agents-main`
**~6,600 LOC — the largest and most feature-complete reference, bilingual (Traditional Chinese) README, real running app with example outputs committed**

- **Purpose**: A 4-agent enterprise SOC deliverable platform built for a specific client ("JJNET"): (1) Incident Investigation Agent — an 8-stage workflow producing an 11-section formal Word/PDF/MD incident report with corporate watermarking; (2) Security Consultant Agent — Q&A over ISO 27001/NIST with citation and an explicit "insufficient evidence → confidence=Low, do not fabricate" rule; (3) Cortex Monthly Report Agent — aggregates SLA metrics (alert volume, MTTA, MTTR, top-10 incidents) into a 5-page executive report; (4) a Training/RAG sign-off system — ingest training material → RAG-generate quiz questions → instructor review/lock → trainee testing → supervisor digital sign-off.
- **Evidence of real output**: repo includes actual generated artifacts — `PA-20260916-89421.docx` (54KB), `.md`, and a `_datapack.json` — suggesting this one has genuinely been run end-to-end against sample data, not just scaffolded.
- **Architecture**: `agent_cli.py` (28KB) as the core orchestrator, a `worker/` directory, a `public/app.js` (97KB) single-page frontend, templates for report generation.
- **Useful ideas**:
  - The **evidence-first / anti-hallucination discipline** ("insufficient basis → explicitly mark Low confidence, never fabricate, list what evidence is still needed") is exactly the principle in Section 17 of our brief and is the most rigorously applied example of it in any reference repo.
  - The **11-section incident report structure** (cover/metadata → exec summary → classification & confidence → affected assets → MITRE mapping → evidence → timeline → response actions → prioritized recommendations → unresolved items → revision/sign-off history) is a stronger, more complete report template than anything else in the reference set and maps closely to Section 24 of our brief.
  - **SLA-metric monthly reporting** (MTTA/MTTR/automation block-rate/weekly trend) is a good pattern for a "Reports" feature beyond single-incident reports.
- **Weakness**: Tightly coupled to one client's branding/watermark/document format; "100% on-prem, data never leaves" is an architectural constraint specific to that engagement, not necessarily ours; no visible automated test suite; no attack-graph visualization; no anomaly-detection ML; correlation logic is not clearly separated from the LLM step (risk of the same "LLM does everything" anti-pattern, just with better output formatting).
- **Verdict: ADOPT the report structure and the evidence/confidence discipline as direct templates. DO NOT adopt the client-specific packaging.**

---

## Cross-Cutting Observations

1. **None of the 8 repos is a complete SOC platform.** They cluster into three unrelated categories:
   - *Deterministic rule engines* (`Agentic-Cybersecurity-Soc-main`) — good detection logic, no AI.
   - *RL training/eval environments* (`CyberSOC-main` v1 and v2) — good for building our evaluation harness, irrelevant to the product itself.
   - *Thin LLM-chain demos* (`cyber-soc-agent-main`, `cyber_soc-main`, `cyberdev-soc-main`, `jjnet-security-agents-main`) — increasing levels of polish, but every one of them is fundamentally the anti-pattern the brief warns about in Section 6 and Section 63: raw events → LLM → text report, with little to no deterministic correlation engine, anomaly-detection model, persistent incident state machine, or human-approval gate in between.
2. **`CyberSocial-main` is unrelated** (an AI-agent social forum) and is excluded entirely.
3. **No repo implements**: PostgreSQL-backed incident state, RAG with reranking, MITRE confidence/evidence separation, a response simulator with human approval gates, an attack graph, or a measured (not claimed) evaluation suite. These are exactly the gaps our architecture needs to fill — which matches the brief's own target architecture rather than any single reference.
4. **Best single ideas to carry forward**, by repo: Agentic-Cybersecurity-Soc (deterministic detection rules + kill-chain mapping), cyberdev-soc (typed structured agent I/O), jjnet (evidence-first discipline + report structure), CyberSOC v1/v2 (typed action schemas + per-scenario graders), cyber_soc (WebSocket live-feed UX).

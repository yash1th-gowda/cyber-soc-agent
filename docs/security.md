# Security

## Threat model
This is a security tool, so it is treated as a target. Event content is **untrusted**; the API has **no authentication** (see Gaps).

## Controls (implemented and tested)
| Area | Control | Evidence |
|---|---|---|
| Input validation | Schema validation (required fields, severity enum, ISO timestamps); `event_id` restricted to `[A-Za-z0-9._\-:]{1,128}`; non-dict payloads rejected; unknown fields preserved, not trusted | `TestMalformedInput`, API 422 tests |
| Evidence integrity | Duplicate `event_id`: identical = no-op, different = rejected (409); original preserved | `TestDuplicates` |
| SQL | Parameterized everywhere; the only dynamic identifier (entity column) is allow-listed | code review (`database/db.py`) |
| XSS | Dashboard passes every event/human-derived value through `esc()`; inline `onclick` handlers removed (listeners + data attributes) | static tests `TestFrontendEscaping`; **no browser-level test exists** |
| Prompt injection | Default provider never calls an LLM, so log text cannot instruct it; payloads in `command`/`message`/`username` verified not to change severity, confidence, approvals, or produce execution claims. `OpenAIProvider.SYSTEM_PROMPT` documents the SYSTEM / trusted data / untrusted log separation | `TestPromptInjection`; the OpenAI path is **unimplemented and unverified** |
| Response safety | Simulation only; `execute_simulated` reachable only from approval; rejected/duplicate decisions fail closed; no subprocess/socket/requests/eval/exec in response or investigation modules | `TestResponseSafety` static scan |
| Error handling | JSON 404/405/500 handlers; no stack traces to clients; Flask debug off by default (`FLASK_DEBUG=1` to opt in); server binds 127.0.0.1 by default | `test_unhandled_exception_returns_clean_500` |
| Secrets | `OPENAI_API_KEY` from environment only; none committed; provider fails closed without it | `test_openai_provider_fails_closed_without_key` |
| Audit | Ingest, alerts, incidents, proposals, approvals/rejections, duplicate conflicts, unhandled exceptions logged | API audit test |
| Limits | `limit` query params clamped to 1..2000; `approved_by` truncated to 64 chars | code |

## Gaps (not fixed, by scope)
1. **No authentication/RBAC** - anyone who can reach the port can approve (simulated) actions and claim any identity. Do not expose it.
2. No rate limiting; SQLite with one locked connection (demo scale).
3. `esc()` fix verified statically/by inspection only (no JS runner in this environment).
4. `POSSIBLE_CREDENTIAL_COMPROMISE` is not retroactively re-evaluated if the success event arrives before its failures.
5. Free-text fields (`message`, `command`) are stored verbatim by design; safety relies on output escaping.
6. OpenAI provider prompt-injection defense is a design, not a tested control.

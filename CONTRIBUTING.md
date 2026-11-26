# Contributing

Thanks for helping improve Cyber SOC Agent.

## Project safety boundaries

- This repository is a local, educational SOC decision-support and response-simulation project.
- Do not add code that performs real firewall, network, host-isolation, account-disable, or session-revocation actions.
- Response recommendations must remain human-reviewed and simulation-only unless the project scope is explicitly redesigned and separately reviewed.
- Treat ingested event fields as untrusted data. Preserve output escaping and prompt-injection boundaries.
- Do not commit credentials, API keys, local databases, event exports containing personal data, or environment files.

## Development setup

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt
python -m unittest discover -s tests -p "test_*.py"
python -m compileall -q backend scripts tests
```

## Pull requests

1. Create a focused branch from `main`.
2. Keep changes scoped and add regression tests for bug fixes.
3. Update documentation when behavior, configuration, or limitations change.
4. Run the complete test suite and compile check.
5. Describe what changed, what was tested, and any remaining limitations in the pull request.
6. Do not rewrite shared Git history or force-push over another contributor's work.

## Reporting security issues

Please do not publish secrets or exploit details in a public issue. Contact the repository maintainer privately through GitHub with a concise description and safe reproduction steps.

"""The single Investigation Agent: turns assembled structured evidence into a narrative."""
from __future__ import annotations

from .llm_provider import LLMProvider, get_provider

REQUIRED_FIELDS = ("incident_summary", "evidence", "attack_sequence", "severity_explanation",
                   "confidence", "alternative_explanation", "missing_evidence",
                   "recommended_next_steps", "recommended_mitigation")


class InvestigationAgent:
    def __init__(self, provider: LLMProvider | None = None):
        self.provider = provider or get_provider()

    def investigate(self, incident: dict, alerts: list) -> dict:
        result = self.provider.generate_investigation({"incident": incident, "alerts": alerts})
        missing = [f for f in REQUIRED_FIELDS if f not in result]
        if missing:
            raise RuntimeError(f"Investigation output missing required fields: {missing}")
        return result

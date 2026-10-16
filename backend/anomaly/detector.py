"""Secondary anomaly SIGNAL (IsolationForest). Never a verdict; labels are only normal/anomalous.
is_demo_mode=True when too few entities exist to fit meaningfully."""
from __future__ import annotations

from collections import defaultdict
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest

FEATURE_NAMES = ["failed_login_count", "success_login_count", "unique_destination_count",
                 "connection_count", "process_create_count", "total_bytes_transferred"]


def extract_features_per_entity(events: list, entity_field: str = "username") -> dict:
    buckets = defaultdict(lambda: {f: 0 for f in FEATURE_NAMES})
    dests = defaultdict(set)
    for e in events:
        key = e.get(entity_field)
        if not key:
            continue
        b = buckets[key]
        t = e["event_type"]
        if t == "login_failure":
            b["failed_login_count"] += 1
        elif t == "login_success":
            b["success_login_count"] += 1
        elif t == "network_connection":
            b["connection_count"] += 1
            if e.get("destination_ip"):
                dests[key].add(e["destination_ip"])
            b["total_bytes_transferred"] += e.get("bytes_transferred") or 0
        elif t == "process_create":
            b["process_create_count"] += 1
    for k, d in dests.items():
        buckets[k]["unique_destination_count"] = len(d)
    return dict(buckets)


class AnomalyDetector:
    MIN_SAMPLES_FOR_REAL_FIT = 12

    def __init__(self, contamination: float = 0.15, random_state: int = 42):
        self.model: Optional[IsolationForest] = None
        self.contamination = contamination
        self.random_state = random_state
        self.is_demo_mode = True

    def fit(self, events: list, entity_field: str = "username") -> int:
        feats = extract_features_per_entity(events, entity_field)
        X = np.array([[v[f] for f in FEATURE_NAMES] for v in feats.values()])
        n = len(X)
        self.is_demo_mode = n < self.MIN_SAMPLES_FOR_REAL_FIT
        if n < 2:
            self.model = None
            return n
        self.model = IsolationForest(contamination=min(self.contamination, 0.5),
                                     random_state=self.random_state, n_estimators=100)
        self.model.fit(X)
        return n

    def score_entity(self, fv: dict) -> dict:
        if self.model is None:
            return {"label": "normal", "score": 0.0, "demo_mode": True,
                    "note": "insufficient baseline data to fit a model"}
        x = np.array([[fv.get(f, 0) for f in FEATURE_NAMES]])
        return {"label": "anomalous" if self.model.predict(x)[0] == -1 else "normal",
                "score": round(float(self.model.decision_function(x)[0]), 4),
                "demo_mode": self.is_demo_mode}

    def score_events(self, events: list, entity_field: str = "username") -> dict:
        if not self.fit(events, entity_field):
            return {}
        out = {}
        for ent, f in extract_features_per_entity(events, entity_field).items():
            s = self.score_entity(f)
            s["features"] = f
            out[ent] = s
        return out

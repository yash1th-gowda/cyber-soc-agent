#!/usr/bin/env python3
"""Replay demo scenarios through the REAL pipeline (ingest_event, then correlation).
  python scripts/replay.py --list | --scenario credential_compromise [--speed 10] | --all"""
import argparse, json, sys, time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from backend.database.db import Database  # noqa: E402
from backend.pipeline import Pipeline  # noqa: E402
from backend.models.schemas import ValidationError  # noqa: E402

SCEN = ROOT / "data" / "scenarios"


def replay(scenario, db_path, speed):
    pipe = Pipeline(Database(db_path))
    events = sorted(scenario["events"], key=lambda e: e["timestamp"])
    print(f"\n=== {scenario['scenario']} ({len(events)} events) ===")
    prev, n_alerts = None, 0
    for e in events:
        ts = datetime.fromisoformat(e["timestamp"])
        if prev and speed > 0:
            time.sleep(min((ts - prev).total_seconds() / speed, 3.0))
        prev = ts
        try:
            r = pipe.ingest_event(e)
        except ValidationError as err:
            print(f"  REJECTED {e.get('event_id')}: {err}")
            continue
        n_alerts += len(r["alerts"])
        print(f"  {e['timestamp']}  {e['event_type']:<24}{' [%d alert(s)]' % len(r['alerts']) if r['alerts'] else ''}")
        for a in r["alerts"]:
            print(f"      -> {a['rule']} (confidence={a['confidence']})")
    incs = pipe.run_correlation()
    print(f"Produced {len(incs)} incident(s) from {n_alerts} alert(s).")
    for i in incs:
        print(f"  {i['incident_id']} [{i['severity'].upper()}] {i['title']}  risk={i['risk_score']}")
        print(f"    chain: {' -> '.join(i['attack_chain']) or '(single-stage)'}")
        print(f"    mitre: {[m['technique_id'] for m in i['mitre_techniques']]}")
    if not incs and not n_alerts:
        print("  No alerts fired (expected for the benign scenario).")
    return {"alerts": n_alerts, "incidents": len(incs)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario"); ap.add_argument("--speed", type=float, default=10.0)
    ap.add_argument("--db", default="cyber_soc_demo.db"); ap.add_argument("--list", action="store_true")
    ap.add_argument("--all", action="store_true")
    a = ap.parse_args()
    files = sorted(SCEN.glob("*.json"))
    if a.list:
        for f in files:
            d = json.loads(f.read_text()); print(f"  {d['scenario']:<26} {d['description']}")
        return
    if a.all:
        for f in files: replay(json.loads(f.read_text()), a.db, a.speed)
        return
    if not a.scenario: ap.error("specify --scenario, --all or --list")
    m = [f for f in files if a.scenario in f.name]
    if not m: sys.exit(f"no scenario matching {a.scenario}")
    replay(json.loads(m[0].read_text()), a.db, a.speed)


if __name__ == "__main__":
    main()

import json, sys, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from backend.database.db import Database
from backend.pipeline import Pipeline
from backend.response import simulator
SCEN = ROOT / "data" / "scenarios"


def load(sub):
    return json.loads(next(SCEN.glob(f"*{sub}*.json")).read_text())


class TestScenarios(unittest.TestCase):
    def run_s(self, sub):
        return Pipeline(Database(":memory:")).run_full_pipeline(load(sub)["events"])

    def test_primary_scenario_one_critical_multistage_incident(self):
        r = self.run_s("credential_compromise")
        self.assertEqual((r["errors"], len(r["incidents"])), ([], 1))
        i = r["incidents"][0]
        self.assertEqual(i["severity"], "critical")
        self.assertEqual({m["technique_id"] for m in i["mitre_techniques"]}, {"T1078", "T1059.001", "T1098", "T1041"})
        self.assertTrue(all(m["evidence"] for m in i["mitre_techniques"]))
        self.assertEqual(i["attack_chain"], ["Valid Account (Possible Compromise)", "PowerShell Execution", "Privilege Escalation", "External Connection"])
        ts = [t["timestamp"] for t in i["timeline"]]
        self.assertEqual(ts, sorted(ts))
        self.assertTrue(i["investigation"]["alternative_explanation"])

    def test_each_malicious_scenario_expected_rule_and_mitre(self):
        expect = {"brute_force": ("BRUTE_FORCE", "T1110"), "suspicious_powershell": ("SUSPICIOUS_POWERSHELL", "T1059.001"),
                  "privilege_escalation": ("PRIVILEGE_ESCALATION", "T1098"), "lateral_movement": ("POSSIBLE_LATERAL_MOVEMENT", "T1021")}
        for sub, (rule, tid) in expect.items():
            db = Database(":memory:"); p = Pipeline(db)
            r = p.run_full_pipeline(load(sub)["events"])
            self.assertEqual(len(r["incidents"]), 1, sub)
            self.assertEqual({a["rule"] for a in db.list_alerts()}, {rule}, sub)
            self.assertEqual([m["technique_id"] for m in r["incidents"][0]["mitre_techniques"]], [tid], sub)

    def test_benign_scenario_zero_alerts(self):
        r = self.run_s("benign_admin")
        self.assertEqual((r["errors"], r["alerts"], len(r["incidents"])), ([], 0, 0))

    def test_all_scenarios_ingest_cleanly(self):
        for f in SCEN.glob("*.json"):
            self.assertEqual(Pipeline(Database(":memory:")).run_full_pipeline(json.loads(f.read_text())["events"])["errors"], [], f.name)

    def test_response_flow(self):
        inc = self.run_s("credential_compromise")["incidents"][0]
        recommendation = next(
            r for r in inc["recommendations"]
            if r["action"] ==
            "Temporarily disable the affected account pending verification"
        )
        action = simulator.propose_action_from_recommendation(
            recommendation, inc
        )
        self.assertEqual(action["status"], "pending_approval")

        result = simulator.approve_action(action, "analyst_01")
        self.assertEqual(result["status"], "simulated")
        self.assertIn("SIMULATED", result["result"])


    def test_persistence_across_reopen(self):
        import tempfile
        import os

        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)

        try:
            with Database(path) as db1:
                result = Pipeline(db1).run_full_pipeline(
                    load("credential_compromise")["events"]
                )
                iid = result["incidents"][0]["incident_id"]

            with Database(path) as db2:
                self.assertEqual(
                    db2.get_incident(iid)["severity"], "critical"
                )
                self.assertEqual(len(db2.list_events()), 9)
                self.assertGreater(len(db2.list_audit()), 0)
        finally:
            if os.path.exists(path):
                os.remove(path)



if __name__ == "__main__":
    unittest.main()

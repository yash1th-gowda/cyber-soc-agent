import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import unittest
from backend.mitre.mapping import map_alert_to_mitre, map_incident, RULE_TO_TECHNIQUE


class TestMitre(unittest.TestCase):
    def test_powershell(self):
        m = map_alert_to_mitre({"rule": "SUSPICIOUS_POWERSHELL", "confidence": 0.75, "evidence": ["e1"]})
        self.assertEqual((m["technique_id"], m["status"]), ("T1059.001", "detected"))

    def test_bruteforce(self):
        m = map_alert_to_mitre({"rule": "BRUTE_FORCE", "confidence": 0.85, "evidence": ["e1", "e2"]})
        self.assertEqual((m["technique_id"], m["evidence"]), ("T1110", ["e1", "e2"]))

    def test_low_confidence_suspected(self):
        self.assertEqual(map_alert_to_mitre({"rule": "SUSPICIOUS_EXTERNAL_CONNECTION", "confidence": 0.55, "evidence": ["e"]})["status"], "suspected")

    def test_unknown_rule_none_never_invented(self):
        self.assertIsNone(map_alert_to_mitre({"rule": "NOT_A_RULE", "confidence": 0.9, "evidence": ["e"]}))

    def test_dedup_merges_evidence_keeps_higher_confidence(self):
        m = map_incident([{"rule": "SUSPICIOUS_EXTERNAL_CONNECTION", "confidence": 0.6, "evidence": ["e1"]},
                          {"rule": "SUSPICIOUS_EXTERNAL_CONNECTION", "confidence": 0.9, "evidence": ["e2"]}])
        self.assertEqual((len(m), set(m[0]["evidence"]), m[0]["confidence"], m[0]["status"]), (1, {"e1", "e2"}, 0.9, "detected"))

    def test_every_rule_has_a_mapping(self):
        from backend.detection.rules import RULES
        self.assertEqual(len(RULE_TO_TECHNIQUE), 7)


if __name__ == "__main__":
    unittest.main()

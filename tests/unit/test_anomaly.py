import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import unittest
from backend.anomaly.detector import AnomalyDetector, extract_features_per_entity


def ev(i, t, **kw):
    d = {"event_id": i, "event_type": t}
    d.update(kw)
    return d


class TestAnomaly(unittest.TestCase):
    def test_feature_extraction(self):
        f = extract_features_per_entity([ev("1", "login_failure", username="a"), ev("2", "login_failure", username="a"),
            ev("3", "login_success", username="a"), ev("4", "network_connection", username="a", destination_ip="1.1.1.1", bytes_transferred=100),
            ev("5", "network_connection", username="a", destination_ip="2.2.2.2", bytes_transferred=200)])["a"]
        self.assertEqual((f["failed_login_count"], f["success_login_count"], f["unique_destination_count"], f["total_bytes_transferred"]), (2, 1, 2, 300))

    def test_small_dataset_is_demo_mode(self):
        d = AnomalyDetector(); d.fit([ev("1", "login_failure", username="a")])
        self.assertTrue(d.is_demo_mode)

    def test_outlier_scored_and_not_demo_with_enough_entities(self):
        d = AnomalyDetector()
        events = [ev(f"n{i}", "login_failure", username=f"user{i}") for i in range(20)]
        events += [ev(f"o{i}", "login_failure", username="outlier") for i in range(30)]
        r = d.score_events(events)
        self.assertIn(r["outlier"]["label"], ("normal", "anomalous"))
        self.assertFalse(d.is_demo_mode)

    def test_vocabulary_never_claims_attack(self):
        d = AnomalyDetector(); d.fit([ev(f"e{i}", "login_failure", username="x") for i in range(3)])
        self.assertIn(d.score_entity({})["label"], ("normal", "anomalous"))


if __name__ == "__main__":
    unittest.main()

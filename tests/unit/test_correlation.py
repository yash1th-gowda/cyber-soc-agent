import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import unittest
from backend.database.db import Database
from backend.pipeline import Pipeline
from backend.models.schemas import ValidationError


def E(i, ts, et, **kw):
    d = {"event_id": i, "timestamp": ts, "source": "test", "event_type": et, "severity": kw.pop("severity", "low")}
    d.update(kw)
    return d


class TestCorrelation(unittest.TestCase):
    def setUp(self):
        self.db = Database(":memory:")
        self.p = Pipeline(self.db)

    def _burst(self, prefix, ip, user, host, hour):
        for i in range(5):
            self.p.ingest_event(E(f"{prefix}{i}", f"2026-01-01T{hour}:0{i}:00", "login_failure", source_ip=ip, username=user, hostname=host))

    def test_events_correlated_into_one_incident(self):
        self._burst("f", "5.5.5.5", "carol", "WS-9", "00")
        self.p.ingest_event(E("p0", "2026-01-01T00:06:00", "process_create", process="powershell.exe", command="powershell -enc X", username="carol", hostname="WS-9"))
        incs = self.p.run_correlation()
        self.assertEqual(len(incs), 1)
        self.assertEqual(len(incs[0]["alert_ids"]), 2)

    def test_unrelated_events_separated(self):
        self._burst("a", "1.1.1.1", "alice", "H-A", "00")
        self._burst("b", "2.2.2.2", "bob", "H-B", "03")
        self.assertEqual(len(self.p.run_correlation()), 2)

    def test_single_alert_still_an_incident(self):
        self.p.ingest_event(E("g1", "2026-01-01T00:00:00", "group_membership_change", username="d", hostname="W", message="d added to Administrators group"))
        incs = self.p.run_correlation()
        self.assertEqual((len(incs), incs[0]["severity"]), (1, "high"))

    def test_same_ip_unrelated_users_and_hosts_still_group_via_shared_ip(self):
        # documents behaviour: shared source_ip is a shared entity, so these merge
        self._burst("x", "7.7.7.7", "u1", "H1", "00")
        self.p.ingest_event(E("y0", "2026-01-01T00:07:00", "process_create", process="powershell.exe", command="powershell -enc X", source_ip="7.7.7.7", username="u2", hostname="H2"))
        self.assertEqual(len(self.p.run_correlation()), 1)

    def test_same_user_different_hosts_no_shared_other_entity_still_groups_by_user(self):
        self._burst("m", "3.3.3.3", "dave", "H1", "00")
        self.p.ingest_event(E("g9", "2026-01-01T00:08:00", "group_membership_change", username="dave", hostname="H9", message="dave added to Administrators group"))
        self.assertEqual(len(self.p.run_correlation()), 1)

    def test_benign_events_do_not_join_malicious_incident(self):
        self._burst("m", "3.3.3.3", "mallory", "H1", "00")
        self.p.ingest_event(E("ok1", "2026-01-01T00:05:00", "login_success", source_ip="10.0.0.9", username="sysadmin", hostname="PRINT-1"))
        incs = self.p.run_correlation()
        self.assertEqual(len(incs), 1)
        self.assertNotIn("ok1", incs[0]["event_ids"])

    def test_same_entity_but_events_hours_apart_do_not_merge(self):
        """Regression: window used ingest wall-clock time, so historical events always merged."""
        self.p.ingest_event(E("g1", "2026-01-01T00:00:00", "group_membership_change", username="zed", hostname="W", message="zed added to Administrators group"))
        self.p.ingest_event(E("p1", "2026-01-01T05:00:00", "process_create", process="powershell.exe", command="powershell -enc X", username="zed", hostname="W"))
        self.assertEqual(len(self.p.run_correlation()), 2)

    def test_same_entity_within_window_merge(self):
        self.p.ingest_event(E("g1", "2026-01-01T00:00:00", "group_membership_change", username="zed", hostname="W", message="zed added to Administrators group"))
        self.p.ingest_event(E("p1", "2026-01-01T00:10:00", "process_create", process="powershell.exe", command="powershell -enc X", username="zed", hostname="W"))
        self.assertEqual(len(self.p.run_correlation()), 1)


if __name__ == "__main__":
    unittest.main()

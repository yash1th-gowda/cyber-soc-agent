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


class Base(unittest.TestCase):
    def setUp(self):
        self.db = Database(":memory:")
        self.p = Pipeline(self.db)

    def rules(self, r):
        return [a["rule"] for a in r["alerts"]]


class TestBruteForce(Base):
    def test_bruteforce_detection_fires_at_threshold(self):
        al = []
        for i in range(5):
            al += self.p.ingest_event(E(f"e{i}", f"2026-01-01T00:0{i}:00", "login_failure", source_ip="1.2.3.4", username="bob"))["alerts"]
        bf = [a for a in al if a["rule"] == "BRUTE_FORCE"]
        self.assertEqual(len(bf), 1)
        self.assertEqual(len(bf[0]["evidence"]), 5)

    def test_not_below_threshold(self):
        al = []
        for i in range(4):
            al += self.p.ingest_event(E(f"e{i}", f"2026-01-01T00:0{i}:00", "login_failure", source_ip="1.2.3.4"))["alerts"]
        self.assertEqual(al, [])

    def test_separate_ips_do_not_combine(self):
        al = []
        for i in range(5):
            al += self.p.ingest_event(E(f"e{i}", f"2026-01-01T00:0{i}:00", "login_failure", source_ip="1.1.1.1" if i % 2 else "2.2.2.2"))["alerts"]
        self.assertEqual(al, [])

    def test_events_outside_window_do_not_combine(self):
        al = []
        for i in range(5):  # 5 failures, each 20 minutes apart (> 10 min window)
            al += self.p.ingest_event(E(f"e{i}", f"2026-01-01T0{i}:00:00", "login_failure", source_ip="9.9.9.9"))["alerts"]
        self.assertEqual(al, [])


class TestCredentialCompromise(Base):
    def test_fires_after_failures_then_success(self):
        for i in range(3):
            self.p.ingest_event(E(f"f{i}", f"2026-01-01T00:0{i}:00", "login_failure", source_ip="9.9.9.9", username="admin"))
        r = self.p.ingest_event(E("s0", "2026-01-01T00:05:00", "login_success", source_ip="9.9.9.9", username="admin"))
        self.assertIn("POSSIBLE_CREDENTIAL_COMPROMISE", self.rules(r))

    def test_clean_login_no_alert(self):
        self.assertEqual(self.p.ingest_event(E("s0", "2026-01-01T00:00:00", "login_success", source_ip="9.9.9.9", username="a"))["alerts"], [])


class TestPowerShell(Base):
    def test_encoded_command_fires(self):
        r = self.p.ingest_event(E("p1", "2026-01-01T00:00:00", "process_create", process="powershell.exe", command="powershell -enc ABCD", hostname="W"))
        self.assertIn("SUSPICIOUS_POWERSHELL", self.rules(r))

    def test_benign_command_silent(self):
        r = self.p.ingest_event(E("p2", "2026-01-01T00:00:00", "process_create", process="powershell.exe", command="Get-Service", hostname="W"))
        self.assertEqual(r["alerts"], [])

    def test_credential_dumping_distinct_rule(self):
        r = self.p.ingest_event(E("p3", "2026-01-01T00:00:00", "process_create", process="powershell.exe", command="Invoke-Mimikatz", hostname="W"))
        self.assertIn("CREDENTIAL_DUMPING_TOOL", self.rules(r))
        self.assertNotIn("SUSPICIOUS_POWERSHELL", self.rules(r))


class TestPrivEsc(Base):
    def test_fires(self):
        r = self.p.ingest_event(E("g1", "2026-01-01T00:00:00", "group_membership_change", username="a", hostname="W", message="a added to Administrators group"))
        self.assertIn("PRIVILEGE_ESCALATION", self.rules(r))

    def test_non_privileged_group_silent(self):
        r = self.p.ingest_event(E("g2", "2026-01-01T00:00:00", "group_membership_change", username="a", hostname="W", message="a added to Marketing group"))
        self.assertEqual(r["alerts"], [])


class TestExternalConnection(Base):
    def test_internal_silent(self):
        self.assertEqual(self.p.ingest_event(E("n1", "2026-01-01T00:00:00", "network_connection", hostname="W", destination_ip="10.0.0.5"))["alerts"], [])

    def test_external_large_transfer_fires(self):
        r = self.p.ingest_event(E("n2", "2026-01-01T00:00:00", "network_connection", hostname="W", destination_ip="8.8.8.8", bytes_transferred=99_000_000))
        self.assertIn("SUSPICIOUS_EXTERNAL_CONNECTION", self.rules(r))


class TestLateral(Base):
    def test_four_hosts_fires(self):
        al = []
        for i, h in enumerate(["H1", "H2", "H3", "H4"]):
            al += self.p.ingest_event(E(f"l{i}", f"2026-01-01T00:0{i}:00", "login_success", username="svc", hostname=h))["alerts"]
        self.assertIn("POSSIBLE_LATERAL_MOVEMENT", [a["rule"] for a in al])

    def test_two_hosts_silent(self):
        al = []
        for i, h in enumerate(["H1", "H2"]):
            al += self.p.ingest_event(E(f"l{i}", f"2026-01-01T00:0{i}:00", "login_success", username="svc", hostname=h))["alerts"]
        self.assertEqual(al, [])


if __name__ == "__main__":
    unittest.main()

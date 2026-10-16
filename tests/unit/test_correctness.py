import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import json, tempfile, unittest
from backend.database.db import Database
from backend.pipeline import Pipeline
from backend.models.schemas import ValidationError
from backend.response import simulator


def E(i, ts, et, **kw):
    d = {"event_id": i, "timestamp": ts, "source": "test", "event_type": et, "severity": kw.pop("severity", "low")}
    d.update(kw)
    return d


def privesc_incident(p):
    p.ingest_event(E("g1", "2026-01-01T00:00:00", "group_membership_change", username="eve", hostname="WS-7", message="eve added to Administrators group"))
    return p.run_correlation()[0]


class TestOutOfOrderIngestion(unittest.TestCase):
    """Regression: backward-only windows made BRUTE_FORCE/LATERAL_MOVEMENT never fire if events arrived out of order."""
    def setUp(self):
        self.db = Database(":memory:"); self.p = Pipeline(self.db)

    def test_bruteforce_regardless_of_ingestion_order(self):
        order = [("o1", "00:04"), ("o2", "00:01"), ("o3", "00:03"), ("o4", "00:00"), ("o5", "00:02")]
        al = []
        for i, t in order:
            al += self.p.ingest_event(E(i, f"2026-01-01T{t}:00", "login_failure", source_ip="7.7.7.7"))["alerts"]
        self.assertEqual([a["rule"] for a in al].count("BRUTE_FORCE"), 1)

    def test_lateral_movement_regardless_of_ingestion_order(self):
        al = []
        for i, (h, t) in enumerate(zip(["H1", "H2", "H3", "H4"], ["06", "00", "04", "02"])):
            al += self.p.ingest_event(E(f"lm{i}", f"2026-01-01T00:{t}:00", "login_success", username="svc", hostname=h))["alerts"]
        self.assertEqual([a["rule"] for a in al].count("POSSIBLE_LATERAL_MOVEMENT"), 1)

    def test_large_burst_fires_exactly_once(self):
        al = []
        for i in range(8):
            al += self.p.ingest_event(E(f"b{i}", f"2026-01-01T00:0{i}:00", "login_failure", source_ip="3.3.3.3"))["alerts"]
        self.assertEqual([a["rule"] for a in al].count("BRUTE_FORCE"), 1)

    def test_two_separate_bursts_fire_twice(self):
        al = []
        for i in range(5):
            al += self.p.ingest_event(E(f"a{i}", f"2026-01-01T00:0{i}:00", "login_failure", source_ip="3.3.3.3"))["alerts"]
        for i in range(5):
            al += self.p.ingest_event(E(f"c{i}", f"2026-01-01T05:0{i}:00", "login_failure", source_ip="3.3.3.3"))["alerts"]
        self.assertEqual([a["rule"] for a in al].count("BRUTE_FORCE"), 2)


class TestDuplicates(unittest.TestCase):
    """Regression: duplicate event_id silently overwrote stored evidence (INSERT OR REPLACE)."""
    def setUp(self):
        self.db = Database(":memory:"); self.p = Pipeline(self.db)

    def test_identical_redelivery_is_noop(self):
        e = E("d1", "2026-01-01T00:00:00", "login_failure", source_ip="1.1.1.1")
        self.p.ingest_event(e)
        r = self.p.ingest_event(dict(e))
        self.assertEqual((r.get("duplicate"), r["alerts"]), ("identical", []))

    def test_conflicting_redelivery_rejected_original_preserved(self):
        self.p.ingest_event(E("d2", "2026-01-01T00:00:00", "login_failure", source_ip="1.1.1.1"))
        with self.assertRaises(ValidationError):
            self.p.ingest_event(E("d2", "2026-01-01T00:00:01", "login_success", source_ip="1.1.1.1"))
        self.assertEqual(self.db.get_event("d2")["event_type"], "login_failure")


class TestMalformedInput(unittest.TestCase):
    def setUp(self):
        self.p = Pipeline(Database(":memory:"))

    def test_unknown_field_tolerated_and_preserved(self):
        r = self.p.ingest_event({"event_id": "x1", "timestamp": "2026-01-01T00:00:00", "source": "t", "event_type": "login_failure", "vendor_field": "v"})
        self.assertIn("_unrecognized_fields", r["event"]["raw_event"])

    def test_bad_timestamp(self):
        with self.assertRaises(ValidationError): self.p.ingest_event({"event_id": "x2", "timestamp": "nope", "source": "t", "event_type": "t"})

    def test_non_dict_payload(self):
        with self.assertRaises(ValidationError): self.p.ingest_event(["a"])

    def test_empty_required_field(self):
        with self.assertRaises(ValidationError): self.p.ingest_event({"event_id": "", "timestamp": "2026-01-01T00:00:00", "source": "t", "event_type": "t"})

    def test_invalid_severity(self):
        with self.assertRaises(ValidationError): self.p.ingest_event({"event_id": "x3", "timestamp": "2026-01-01T00:00:00", "source": "t", "event_type": "t", "severity": "apocalyptic"})

    def test_unknown_event_type_no_crash_no_alert(self):
        self.assertEqual(self.p.ingest_event({"event_id": "x4", "timestamp": "2026-01-01T00:00:00", "source": "t", "event_type": "alien"})["alerts"], [])

    def test_html_shaped_event_id_rejected(self):
        with self.assertRaises(ValidationError): self.p.ingest_event({"event_id": "<img src=x onerror=alert(1)>", "timestamp": "2026-01-01T00:00:00", "source": "t", "event_type": "t"})

    def test_normal_identifier_accepted(self):
        self.assertEqual(self.p.ingest_event({"event_id": "evt-001_a.b:c", "timestamp": "2026-01-01T00:00:00", "source": "t", "event_type": "t"})["event"]["event_id"], "evt-001_a.b:c")

    def test_html_in_free_text_stored_verbatim(self):
        r = self.p.ingest_event({"event_id": "x5", "timestamp": "2026-01-01T00:00:00", "source": "t", "event_type": "t", "message": "<script>alert(1)</script>"})
        self.assertEqual(r["event"]["message"], "<script>alert(1)</script>")


class TestFrontendEscaping(unittest.TestCase):
    """Static guard (no JS runner available): dashboard defines esc() and has no inline handlers."""
    def test_dashboard_has_escape_helper_and_no_inline_handlers(self):
        s = (ROOT / "frontend" / "dashboard.html").read_text()
        self.assertIn("function esc(", s)
        self.assertNotIn("onclick=", s)
        for ch in ("&amp;", "&lt;", "&gt;", "&quot;", "&#39;"):
            self.assertIn(ch, s)

    def test_event_derived_fields_are_escaped_in_templates(self):
        import re
        s = (ROOT / "frontend" / "dashboard.html").read_text()
        for field in ("t.description", "i.title", "inv.incident_summary", "a.target", "a.result", "x.reasoning"):
            hits = re.findall(r"\$\{([^}]*" + re.escape(field) + r"[^}]*)\}", s)
            self.assertTrue(hits, f"{field} not rendered?")
            for h in hits:
                self.assertIn("esc(", h, f"{field} rendered without esc(): {h}")


if __name__ == "__main__":
    unittest.main()

import json, os, sys, tempfile, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from backend.api.app import create_app
SCEN = ROOT / "data" / "scenarios"
PRIV = [{"event_id": "mi1", "timestamp": "2026-01-01T00:00:00", "source": "t", "event_type": "group_membership_change",
         "username": "x", "hostname": "h", "message": "x added to Administrators group"}]


class TestAPI(unittest.TestCase):

    def setUp(self):
        self.path = tempfile.mktemp(suffix=".db")
        self.app = create_app(self.path)
        self.c = self.app.test_client()
        self.extra_apps = []

    def tearDown(self):
        # Close every app's database connection before deleting the file.
        apps = self.extra_apps + [self.app]
        seen = set()

        for app in apps:
            db = app.config.get("DB")
            if db is not None and id(db) not in seen:
                seen.add(id(db))
                db.close()

        if os.path.exists(self.path):
            os.remove(self.path)

    def inc(self, events=PRIV):
        return self.c.post("/events/upload", json={"events": events}).json["incidents"][0]

    def test_health(self):
        self.assertEqual(self.c.get("/health").json["status"], "ok")

    def test_validation_422(self):
        self.assertEqual(self.c.post("/events", json={"event_id": "x"}).status_code, 422)

    def test_non_json_400(self):
        self.assertEqual(self.c.post("/events", data="not json", content_type="application/json").status_code, 400)

    def test_valid_event_201(self):
        self.assertEqual(self.c.post("/events", json={"event_id": "e1", "timestamp": "2026-01-01T00:00:00", "source": "t", "event_type": "login_success"}).status_code, 201)

    def test_all_incident_routes(self):
        events = json.loads((SCEN / "02_credential_compromise.json").read_text())["events"]
        iid = self.inc(events)["incident_id"]
        for suffix in ("", "/timeline", "/evidence", "/mitre", "/risk"):
            self.assertEqual(self.c.get(f"/incidents/{iid}{suffix}").status_code, 200, suffix)
        self.assertEqual(self.c.post(f"/incidents/{iid}/investigate").status_code, 200)
        self.assertEqual(self.c.get(f"/reports/{iid}").status_code, 200)
        self.assertEqual(self.c.get(f"/reports/{iid}?format=markdown").status_code, 200)

    def test_unknown_ids_404(self):
        for url in ("/incidents/INC-NOPE", "/incidents/INC-NOPE/timeline", "/reports/INC-NOPE"):
            self.assertEqual(self.c.get(url).status_code, 404, url)
        self.assertEqual(self.c.post("/actions/ACT-NOPE/approve").status_code, 404)
        self.assertEqual(self.c.post("/actions/ACT-NOPE/reject").status_code, 404)
        self.assertEqual(self.c.post("/incidents/INC-NOPE/actions", json={"recommendation_index": 0}).status_code, 404)
        self.assertEqual(self.c.get("/nope").json, {"error": "not found"})


    def test_approve_workflow_and_double_approval_409(self):
        events = json.loads(
            (SCEN / "02_credential_compromise.json").read_text()
        )["events"]
        iid = self.inc(events)["incident_id"]

        incident = self.c.get(f"/incidents/{iid}").json
        idx = next(
            k for k, rec in enumerate(incident["recommendations"])
            if rec["action"] ==
            "Temporarily disable the affected account pending verification"
        )

        a = self.c.post(
            f"/incidents/{iid}/actions",
            json={"recommendation_index": idx},
        )
        self.assertEqual((a.status_code, a.json["status"]), (201, "pending_approval"))

        aid = a.json["action_id"]
        r = self.c.post(
            f"/actions/{aid}/approve",
            json={"approved_by": "analyst_01"},
        )
        self.assertEqual(r.json["status"], "simulated")
        self.assertEqual(self.c.post(f"/actions/{aid}/approve").status_code, 409)
        self.assertEqual(self.c.post(f"/actions/{aid}/reject").status_code, 409)

        audit = self.c.get("/audit").json
        self.assertTrue(any(
            x["action"] == "approve_response" and x["actor"] == "analyst_01"
            for x in audit
        ))
        self.assertIn(
            "SIMULATED",
            self.c.get(f"/reports/{iid}?format=markdown").data.decode(),
        )



    def test_reject_workflow_never_simulates(self):
        events = json.loads(
            (SCEN / "02_credential_compromise.json").read_text()
        )["events"]
        iid = self.inc(events)["incident_id"]

        incident = self.c.get(f"/incidents/{iid}").json
        idx = next(
            k for k, rec in enumerate(incident["recommendations"])
            if rec["action"] ==
            "Temporarily disable the affected account pending verification"
        )

        response = self.c.post(
            f"/incidents/{iid}/actions",
            json={"recommendation_index": idx},
        )
        self.assertEqual(response.status_code, 201)

        aid = response.json["action_id"]
        r = self.c.post(
            f"/actions/{aid}/reject",
            json={"rejected_by": "analyst_01"},
        )
        self.assertEqual(r.json["status"], "rejected")
        self.assertNotIn("SIMULATED:", r.json.get("result", ""))
        self.assertEqual(
            self.c.get(f"/incidents/{iid}").json["response_actions"], []
        )


    def test_bad_recommendation_index_400_no_traceback(self):
        iid = self.inc()["incident_id"]
        for bad in ("not_a_number", True, -1, 999, None, 1.5):
            r = self.c.post(f"/incidents/{iid}/actions", json={"recommendation_index": bad})
            self.assertEqual(r.status_code, 400, bad)
            self.assertNotIn("Traceback", r.data.decode())

    def test_duplicate_conflict_409(self):
        base = {"event_id": "dupapi", "timestamp": "2026-01-01T00:00:00", "source": "t", "event_type": "login_failure"}
        self.assertEqual(self.c.post("/events", json=base).status_code, 201)
        self.assertEqual(self.c.post("/events", json=dict(base, event_type="login_success")).status_code, 409)

    def test_xss_shaped_identifier_rejected_free_text_stored(self):
        self.assertEqual(self.c.post("/events", json={"event_id": "<script>alert(1)</script>", "timestamp": "2026-01-01T00:00:00", "source": "t", "event_type": "t"}).status_code, 422)
        r = self.c.post("/events", json={"event_id": "xss1", "timestamp": "2026-01-01T00:00:00", "source": "t", "event_type": "t", "message": "<img src=x onerror=alert(1)>"})
        self.assertEqual(r.json["event"]["message"], "<img src=x onerror=alert(1)>")

    def test_unhandled_exception_returns_clean_500(self):
        app = create_app(self.path)
        self.extra_apps.append(app)
        @app.route("/boom")
        def boom(): raise RuntimeError("secret internals /home/x/app.py")
        r = app.test_client().get("/boom")
        self.assertEqual(r.status_code, 500)
        body = r.data.decode()
        self.assertEqual(json.loads(body), {"error": "internal server error"})
        self.assertNotIn("secret internals", body)

    def test_upload_requires_events_list(self):
        self.assertEqual(self.c.post("/events/upload", json={"events": "nope"}).status_code, 400)

    def test_dashboard_and_summary(self):
        self.assertEqual(self.c.get("/dashboard/summary").status_code, 200)
        self.assertIn(b"CYBER", self.c.get("/").data)

    def test_state_consistent_across_api_views(self):
        events = json.loads((SCEN / "02_credential_compromise.json").read_text())["events"]
        i = self.inc(events)
        iid = i["incident_id"]
        rep = self.c.get(f"/reports/{iid}").json
        self.assertEqual((rep["severity"], rep["risk_score"]), (i["severity"], i["risk_score"]))
        self.assertEqual(self.c.get(f"/incidents/{iid}/risk").json["total"], i["risk_score"])
        self.assertEqual(self.c.get("/dashboard/summary").json["total_incidents"], 1)


if __name__ == "__main__":
    unittest.main()

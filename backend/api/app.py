"""API layer (Flask; FastAPI was preferred but the build sandbox had no network to install it)."""
from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from backend.database.db import Database
from backend.investigation.agent import InvestigationAgent
from backend.models.schemas import ValidationError
from backend.pipeline import Pipeline
from backend.reporting.report_generator import generate_json_report, generate_markdown_report
from backend.response import simulator
from backend.risk.scoring import explain_risk_score

FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"


def create_app(db_path: str = "cyber_soc.db") -> Flask:
    app = Flask(__name__, static_folder=None)
    db = Database(db_path)
    pipeline = Pipeline(db)
    app.config["DB"], app.config["PIPELINE"] = db, pipeline

    # Backstop: never leak a stack trace to a client, regardless of debug mode.
    @app.errorhandler(404)
    def _nf(e):
        return jsonify({"error": "not found"}), 404

    @app.errorhandler(405)
    def _na(e):
        return jsonify({"error": "method not allowed"}), 405

    @app.errorhandler(500)
    def _ie(e):
        db.audit("system", "unhandled_exception", result="error", details={"error_type": type(e).__name__})
        return jsonify({"error": "internal server error"}), 500

    @app.route("/")
    def index():
        return send_from_directory(FRONTEND_DIR, "dashboard.html")

    @app.route("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.route("/events", methods=["POST"])
    def post_event():
        raw = request.get_json(force=True, silent=True)
        if raw is None:
            return jsonify({"error": "request body must be JSON"}), 400
        try:
            result = pipeline.ingest_event(raw)
        except ValidationError as e:
            return jsonify({"error": str(e)}), (409 if "already exists" in str(e) else 422)
        except TypeError as e:
            return jsonify({"error": f"invalid event fields: {e}"}), 422
        return jsonify(result), 201

    @app.route("/events/upload", methods=["POST"])
    def upload_events():
        raw = request.get_json(force=True, silent=True)
        if not isinstance(raw, dict) or not isinstance(raw.get("events"), list):
            return jsonify({"error": 'request body must be {"events": [...]}'}), 400
        return jsonify(pipeline.run_full_pipeline(raw["events"])), 201

    def _limit(default):
        try:
            return max(1, min(int(request.args.get("limit", default)), 2000))
        except ValueError:
            return default

    @app.route("/events", methods=["GET"])
    def list_events():
        return jsonify(db.list_events(limit=_limit(500)))

    @app.route("/alerts", methods=["GET"])
    def list_alerts():
        return jsonify(db.list_alerts(limit=_limit(500)))

    @app.route("/incidents", methods=["GET"])
    def list_incidents():
        return jsonify(db.list_incidents(limit=_limit(200)))

    def _inc_or_404(incident_id):
        inc = db.get_incident(incident_id)
        return inc, (None if inc else (jsonify({"error": "incident not found"}), 404))

    @app.route("/incidents/<incident_id>", methods=["GET"])
    def get_incident(incident_id):
        inc, err = _inc_or_404(incident_id)
        return err or jsonify(inc)

    @app.route("/incidents/<incident_id>/timeline", methods=["GET"])
    def get_timeline(incident_id):
        inc, err = _inc_or_404(incident_id)
        return err or jsonify(inc.get("timeline", []))

    @app.route("/incidents/<incident_id>/evidence", methods=["GET"])
    def get_evidence(incident_id):
        inc, err = _inc_or_404(incident_id)
        if err:
            return err
        return jsonify([e for e in (db.get_event(i) for i in inc.get("evidence", [])) if e])

    @app.route("/incidents/<incident_id>/mitre", methods=["GET"])
    def get_mitre(incident_id):
        inc, err = _inc_or_404(incident_id)
        return err or jsonify(inc.get("mitre_techniques", []))

    @app.route("/incidents/<incident_id>/risk", methods=["GET"])
    def get_risk(incident_id):
        inc, err = _inc_or_404(incident_id)
        return err or jsonify(explain_risk_score(inc))

    @app.route("/incidents/<incident_id>/investigate", methods=["POST"])
    def reinvestigate(incident_id):
        inc, err = _inc_or_404(incident_id)
        if err:
            return err
        alerts = [a for a in db.list_alerts(limit=2000) if a.get("incident_id") == incident_id]
        inc["investigation"] = InvestigationAgent().investigate(inc, alerts)
        db.insert_incident(inc)
        db.audit("analyst", "reinvestigate", target=incident_id, result="success")
        return jsonify(inc["investigation"])

    @app.route("/incidents/<incident_id>/actions", methods=["POST"])
    def propose_action(incident_id):
        inc, err = _inc_or_404(incident_id)
        if err:
            return err
        body = request.get_json(force=True, silent=True) or {}
        idx, recs = body.get("recommendation_index"), inc.get("recommendations", [])
        if not isinstance(idx, int) or isinstance(idx, bool) or not (0 <= idx < len(recs)):
            return jsonify({"error": f"recommendation_index must be an integer in [0,{len(recs)})"}), 400
        action = simulator.propose_action_from_recommendation(recs[idx], inc)
        if not action:
            return jsonify({
                "error": "This recommendation is investigation-only or has no supported simulated response action.",
                "recommendation": recs[idx].get("action", ""),
                "supported_actions": [
                    "BLOCK_IP",
                    "ISOLATE_HOST",
                    "DISABLE_USER",
                    "REVOKE_SESSION",
                    "BLOCK_DOMAIN",
                ],
            }), 400
        db.insert_response_action(action)
        db.audit("system", "action_proposed", target=action["action_id"], result="pending_approval")
        return jsonify(action), 201


    def _decide(action_id, approve: bool):
        action = db.get_response_action(action_id)
        if not action:
            return jsonify({"error": "action not found"}), 404

        body = request.get_json(force=True, silent=True) or {}
        who = str(
            body.get("approved_by" if approve else "rejected_by", "analyst")
        )[:64]

        try:
            result = (
                simulator.approve_action(action, who)
                if approve
                else simulator.reject_action(action, who)
            )
        except ValueError as e:
            return jsonify({"error": str(e)}), 409

        # Persist the authoritative action state first.
        db.insert_response_action(result)


        # Keep the incident's response_actions list consistent with
        # the existing API contract: only approved/simulated actions
        # are included; rejected actions remain in the action table
        # and audit trail.
        inc = db.get_incident(result["incident_id"])
        if inc:
            actions = inc.get("response_actions", [])
            actions = [
                existing for existing in actions
                if existing.get("action_id") != result["action_id"]
            ]

            if approve:
                actions.append(result)

            inc["response_actions"] = actions
            db.insert_incident(inc)


        db.audit(
            who,
            "approve_response" if approve else "reject_response",
            target=result["target"],
            result="simulated" if approve else "rejected",
            details={
                "incident_id": result["incident_id"],
                "action_id": action_id,
            },
        )
        return jsonify(result)

    @app.route("/actions/<action_id>/approve", methods=["POST"])
    def approve_route(action_id):
        return _decide(action_id, True)

    @app.route("/actions/<action_id>/reject", methods=["POST"])
    def reject_route(action_id):
        return _decide(action_id, False)

    @app.route("/reports/<incident_id>", methods=["GET"])
    def get_report(incident_id):
        inc, err = _inc_or_404(incident_id)
        if err:
            return err
        if request.args.get("format") == "markdown":
            return generate_markdown_report(inc), 200, {"Content-Type": "text/markdown; charset=utf-8"}
        return jsonify(generate_json_report(inc))

    @app.route("/dashboard/summary", methods=["GET"])
    def summary():
        incs, alerts, events = db.list_incidents(1000), db.list_alerts(1000), db.list_events(1000)
        sev = {}
        for i in incs:
            sev[i["severity"]] = sev.get(i["severity"], 0) + 1
        return jsonify({"total_events": len(events), "total_alerts": len(alerts),
                        "total_incidents": len(incs),
                        "open_incidents": len([i for i in incs if i["status"] not in ("resolved", "false_positive")]),
                        "critical_high_incidents": sev.get("critical", 0) + sev.get("high", 0),
                        "severity_distribution": sev})

    @app.route("/audit", methods=["GET"])
    def audit():
        return jsonify(db.list_audit(limit=_limit(200)))

    @app.route("/demo/reset", methods=["POST"])
    def reset():
        db.reset()
        return jsonify({"status": "reset"})

    return app


if __name__ == "__main__":
    application = create_app(os.environ.get("DB_PATH", "cyber_soc.db"))
    # debug OFF by default: Flask's debugger leaks stack traces/source. Opt in with FLASK_DEBUG=1 (local only).
    application.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)),
                    debug=os.environ.get("FLASK_DEBUG", "0") == "1")

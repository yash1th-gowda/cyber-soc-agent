"""
R1 regression tests: who closes the SQLite connection, and when.

- scripts/replay.py owns the Database it opens and must close it on every exit path.
- backend/api/app.py's standalone entry point (`python -m backend.api.app`) must close the
  application's Database when the server stops, but create_app() itself must NOT close it
  (tests, WSGI servers and imports build apps without ever running __main__).

All tests use a uniquely named database inside a TemporaryDirectory; no project database
(cyber_soc.db, cyber_soc_demo.db) is touched. Cleanup of the directory also fails loudly on
Windows if a connection was leaked, which is exactly the failure this guards against.
"""
import contextlib
import importlib.util
import io
import json
import os
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import flask  # noqa: E402
from backend.api.app import create_app  # noqa: E402
from backend.database.db import Database  # noqa: E402

REPLAY_PATH = ROOT / "scripts" / "replay.py"
APP_PATH = ROOT / "backend" / "api" / "app.py"
SCENARIO = json.loads(next((ROOT / "data" / "scenarios").glob("*credential_compromise*.json")).read_text())


def load_replay_module():
    spec = importlib.util.spec_from_file_location("replay_under_test", REPLAY_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def assert_closed(testcase, db):
    with testcase.assertRaises(RuntimeError) as ctx:
        db.list_events()
    testcase.assertIn("closed", str(ctx.exception))


class TempDbCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)  # registered first => runs last, after connections are closed
        self.db_path = str(Path(tmp.name) / "lifecycle_test.db")
        self.opened = []
        self.addCleanup(self._close_everything)  # safety net so a failing test cannot leak a handle

    def _close_everything(self):
        for db in self.opened:
            db.close()  # idempotent


class TestReplayDatabaseLifecycle(TempDbCase):
    def setUp(self):
        super().setUp()
        self.replay = load_replay_module()
        opened = self.opened

        class RecordingDatabase(Database):
            def __init__(self, *a, **k):
                super().__init__(*a, **k)
                opened.append(self)

        patcher = mock.patch.object(self.replay, "Database", RecordingDatabase)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_replay(self):
        with contextlib.redirect_stdout(io.StringIO()):
            return self.replay.replay(SCENARIO, self.db_path, speed=0)

    def test_replay_closes_its_database_after_success(self):
        result = self.run_replay()
        self.assertEqual(result, {"alerts": 5, "incidents": 1})  # behaviour unchanged
        self.assertEqual(len(self.opened), 1)
        assert_closed(self, self.opened[0])

    def test_replay_commits_before_closing(self):
        self.run_replay()
        with Database(self.db_path) as fresh:  # a new connection, as after a restart
            self.assertEqual(len(fresh.list_incidents()), 1)
            self.assertEqual(len(fresh.list_events()), 9)

    def test_replay_closes_database_and_propagates_exception_from_correlation(self):
        class Boom:
            def __init__(self, db):
                self.db = db

            def ingest_event(self, e):
                return {"alerts": []}

            def run_correlation(self):
                raise RuntimeError("boom in correlation")

        with mock.patch.object(self.replay, "Pipeline", Boom):
            with self.assertRaisesRegex(RuntimeError, "boom in correlation"):
                self.run_replay()
        self.assertEqual(len(self.opened), 1)
        assert_closed(self, self.opened[0])

    def test_replay_closes_database_and_propagates_unexpected_ingest_exception(self):
        class Boom:
            def __init__(self, db):
                self.db = db

            def ingest_event(self, e):
                raise KeyError("unexpected ingest failure")

        with mock.patch.object(self.replay, "Pipeline", Boom):
            with self.assertRaisesRegex(KeyError, "unexpected ingest failure"):
                self.run_replay()
        assert_closed(self, self.opened[0])

    def test_each_replay_call_owns_a_distinct_connection(self):
        # mirrors `replay.py --all`: sequential calls against the same file
        self.run_replay()
        self.run_replay()
        self.assertEqual(len(self.opened), 2)
        self.assertIsNot(self.opened[0], self.opened[1])
        for db in self.opened:
            assert_closed(self, db)


class TestStandaloneEntryPointLifecycle(TempDbCase):
    """Executes the real `if __name__ == "__main__"` block of app.py with Flask.run replaced by a
    stub, so no server is started and no timing/sleeps/signals are involved."""

    def run_main(self, fake_run, extra_env=None):
        captured = {}

        def recording_run(app_self, *args, **kwargs):
            captured["app"], captured["kwargs"] = app_self, kwargs
            self.opened.append(app_self.config["DB"])
            return fake_run(app_self)

        env = {"DB_PATH": self.db_path}
        env.update(extra_env or {})
        with mock.patch.dict(os.environ, env):
            for var in ("HOST", "PORT", "FLASK_DEBUG"):
                if var not in (extra_env or {}):
                    os.environ.pop(var, None)
            with mock.patch.object(flask.Flask, "run", recording_run):
                try:
                    runpy.run_path(str(APP_PATH), run_name="__main__")
                finally:
                    self.captured = captured

    def test_database_is_closed_when_server_returns_normally(self):
        self.run_main(lambda app: None)
        assert_closed(self, self.captured["app"].config["DB"])

    def test_database_is_closed_and_original_exception_propagates(self):
        for exc in (RuntimeError("server crashed"), KeyboardInterrupt()):
            with self.subTest(exc=type(exc).__name__):
                def boom(app, _exc=exc):
                    raise _exc
                with self.assertRaises(type(exc)) as ctx:
                    self.run_main(boom)
                self.assertIs(ctx.exception, exc)  # not replaced or wrapped by cleanup
                assert_closed(self, self.captured["app"].config["DB"])

    def test_database_stays_open_while_server_is_running(self):
        seen = {}

        def during_run(app):
            seen["usable"] = app.config["DB"].list_events() == []
            seen["http_ok"] = app.test_client().get("/health").status_code == 200

        self.run_main(during_run)
        self.assertEqual(seen, {"usable": True, "http_ok": True})

    def test_run_arguments_are_preserved(self):
        self.run_main(lambda app: None)
        self.assertEqual(self.captured["kwargs"], {"host": "127.0.0.1", "port": 5000, "debug": False})
        self.run_main(lambda app: None, {"HOST": "0.0.0.0", "PORT": "5055", "FLASK_DEBUG": "1"})
        self.assertEqual(self.captured["kwargs"], {"host": "0.0.0.0", "port": 5055, "debug": True})


class TestAppFactoryDoesNotOwnShutdown(TempDbCase):
    def test_create_app_keeps_database_open_across_requests(self):
        app = create_app(self.db_path)
        self.opened.append(app.config["DB"])
        client = app.test_client()
        for _ in range(3):  # no per-request teardown may close the shared connection
            self.assertEqual(client.get("/health").status_code, 200)
            self.assertEqual(client.get("/events").status_code, 200)
        self.assertEqual(app.config["DB"].list_events(), [])  # still usable; closing is the caller's job


if __name__ == "__main__":
    unittest.main()

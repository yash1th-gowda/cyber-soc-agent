import subprocess
from unittest.mock import patch

from backend.database.db import Database
from backend.pipeline import Pipeline

from backend.ingestion.windows_security_collector import (
    WindowsSecurityEventCollectionError,
    read_windows_security_events,
    ingest_windows_security_events,
)
import unittest

from backend.ingestion.windows_security_collector import (
    WindowsSecurityEventParseError,
    normalize_windows_security_event,
)


def make_security_xml(
    event_id="4625",
    logon_type="2",
    record_id="1001",
    channel="Security",
    extra_data="",
    timestamp="2026-11-21T10:00:00.0000000Z",
    source_ip="192.168.1.10",
    username="testuser",
):
    return f"""\
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
        <Provider Name="Microsoft-Windows-Security-Auditing"
                  Guid="{{54849625-5478-4994-a5ba-3e3b0328c30d}}"/>
        <EventID>{event_id}</EventID>
        <TimeCreated SystemTime="{timestamp}"/>
        <EventRecordID>{record_id}</EventRecordID>
        <Channel>{channel}</Channel>
        <Computer>TEST-PC</Computer>
    </System>
    <EventData>
        <Data Name="TargetUserName">{username}</Data>
        <Data Name="LogonType">{logon_type}</Data>
        <Data Name="IpAddress">{source_ip}</Data>
        <Data Name="ProcessName">C:\\Windows\\System32\\test.exe</Data>
        {extra_data}
    </EventData>
</Event>
"""
    return f"""\
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
        <Provider Name="Microsoft-Windows-Security-Auditing"
                  Guid="{{54849625-5478-4994-a5ba-3e3b0328c30d}}"/>
        <EventID>{event_id}</EventID>
        <TimeCreated SystemTime="2026-11-21T10:00:00.0000000Z"/>
        <EventRecordID>{record_id}</EventRecordID>
        <Channel>{channel}</Channel>
        <Computer>TEST-PC</Computer>
    </System>
    <EventData>
        <Data Name="TargetUserName">testuser</Data>
        <Data Name="LogonType">{logon_type}</Data>
        <Data Name="IpAddress">192.168.1.10</Data>
        <Data Name="ProcessName">C:\\Windows\\System32\\test.exe</Data>
        {extra_data}
    </EventData>
</Event>
"""


class TestWindowsSecurityEventNormalizer(unittest.TestCase):

    def test_normalizes_failed_logon(self):
        event = normalize_windows_security_event(make_security_xml())

        self.assertIsNotNone(event)
        self.assertEqual(event["event_type"], "login_failure")
        self.assertEqual(event["username"], "testuser")
        self.assertEqual(event["source_ip"], "192.168.1.10")
        self.assertEqual(event["hostname"], "TEST-PC")
        self.assertEqual(event["raw_event"]["logon_type"], 2)
        self.assertEqual(
            event["raw_event"]["windows_event_id"],
            "4625",
        )

    def test_normalizes_supported_successful_logon(self):
        event = normalize_windows_security_event(
            make_security_xml(event_id="4624", logon_type="2")
        )

        self.assertIsNotNone(event)
        self.assertEqual(event["event_type"], "login_success")

    def test_ignores_service_logon(self):
        event = normalize_windows_security_event(
            make_security_xml(event_id="4624", logon_type="5")
        )

        self.assertIsNone(event)

    def test_ignores_unsupported_failed_logon_type(self):
        event = normalize_windows_security_event(
            make_security_xml(event_id="4625", logon_type="5")
        )

        self.assertIsNone(event)

    def test_supports_network_logon_type(self):
        event = normalize_windows_security_event(
            make_security_xml(logon_type="3")
        )

        self.assertIsNotNone(event)
        self.assertEqual(event["event_type"], "login_failure")

    def test_supports_remote_interactive_logon_type(self):
        event = normalize_windows_security_event(
            make_security_xml(event_id="4624", logon_type="10")
        )

        self.assertIsNotNone(event)
        self.assertEqual(event["event_type"], "login_success")

    def test_ignores_other_event_ids(self):
        event = normalize_windows_security_event(
            make_security_xml(event_id="4634")
        )

        self.assertIsNone(event)

    def test_rejects_non_security_channel(self):
        with self.assertRaises(WindowsSecurityEventParseError):
            normalize_windows_security_event(
                make_security_xml(channel="System")
            )

    def test_rejects_invalid_xml(self):
        with self.assertRaises(WindowsSecurityEventParseError):
            normalize_windows_security_event("<Event>")

    def test_rejects_empty_input(self):
        with self.assertRaises(WindowsSecurityEventParseError):
            normalize_windows_security_event("")

    def test_rejects_missing_logon_type(self):
        xml = make_security_xml().replace(
            '<Data Name="LogonType">2</Data>',
            "",
        )

        with self.assertRaises(WindowsSecurityEventParseError):
            normalize_windows_security_event(xml)

    def test_rejects_invalid_logon_type(self):
        with self.assertRaises(WindowsSecurityEventParseError):
            normalize_windows_security_event(
                make_security_xml(logon_type="invalid")
            )

    def test_event_id_is_deterministic(self):
        xml = make_security_xml()

        first = normalize_windows_security_event(xml)
        second = normalize_windows_security_event(xml)

        self.assertEqual(first["event_id"], second["event_id"])

    def test_different_record_ids_produce_different_event_ids(self):
        first = normalize_windows_security_event(
            make_security_xml(record_id="1001")
        )
        second = normalize_windows_security_event(
            make_security_xml(record_id="1002")
        )

        self.assertNotEqual(first["event_id"], second["event_id"])

    def test_preserves_original_xml_and_failure_details(self):
        xml = make_security_xml(
            extra_data=(
                '<Data Name="Status">0xc000006d</Data>'
                '<Data Name="SubStatus">0xc000006a</Data>'
                '<Data Name="FailureReason">%%2313</Data>'
            )
        )

        event = normalize_windows_security_event(xml)

        self.assertEqual(event["raw_event"]["xml"], xml)
        self.assertEqual(
            event["raw_event"]["event_data"]["Status"],
            "0xc000006d",
        )
        self.assertEqual(
            event["raw_event"]["event_data"]["SubStatus"],
            "0xc000006a",
        )
        self.assertEqual(
            event["raw_event"]["event_data"]["FailureReason"],
            "%%2313",
        )

    def test_missing_ip_address_becomes_none(self):
        xml = make_security_xml().replace(
            '<Data Name="IpAddress">192.168.1.10</Data>',
            '<Data Name="IpAddress">-</Data>',
        )

        event = normalize_windows_security_event(xml)

        self.assertIsNone(event["source_ip"])


class TestWindowsSecurityEventReader(unittest.TestCase):

    @patch("backend.ingestion.windows_security_collector.subprocess.run")
    def test_reads_security_xml_records(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout='["<Event>one</Event>", "<Event>two</Event>"]',
            stderr="",
        )

        records = read_windows_security_events(2)

        self.assertEqual(len(records), 2)
        self.assertEqual(records[0], "<Event>one</Event>")
        self.assertEqual(mock_run.call_args.kwargs["timeout"], 30)

    def test_rejects_invalid_event_limits(self):
        for value in (0, -1, 1001, True, "3"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    read_windows_security_events(value)

    @patch("backend.ingestion.windows_security_collector.subprocess.run")
    def test_handles_powershell_failure(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr="Access denied",
        )

        with self.assertRaises(WindowsSecurityEventCollectionError):
            read_windows_security_events(3)

    @patch("backend.ingestion.windows_security_collector.subprocess.run")
    def test_handles_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd="powershell.exe",
            timeout=30,
        )

        with self.assertRaises(WindowsSecurityEventCollectionError):
            read_windows_security_events(3)

    @patch("backend.ingestion.windows_security_collector.subprocess.run")
    def test_rejects_invalid_json(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="not-json",
            stderr="",
        )

        with self.assertRaises(WindowsSecurityEventCollectionError):
            read_windows_security_events(3)

    @patch("backend.ingestion.windows_security_collector.subprocess.run")
    def test_rejects_non_array_result(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout='"<Event/>"',
            stderr="",
        )

        with self.assertRaises(WindowsSecurityEventCollectionError):
            read_windows_security_events(3)

    @patch("backend.ingestion.windows_security_collector.subprocess.run")
    def test_empty_collection_returns_empty_list(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="[]",
            stderr="",
        )

        self.assertEqual(read_windows_security_events(3), [])


class TestWindowsSecurityEventIngestion(unittest.TestCase):

    @patch(
        "backend.ingestion.windows_security_collector.read_windows_security_events"
    )
    def test_ingests_supported_event_and_ignores_service_logon(self, mock_read):
        sample_4624 = make_security_xml(
            event_id="4624",
            logon_type="5",
        )

        sample_4625 = make_security_xml(
            event_id="4625",
            logon_type="2",
        )

        mock_read.return_value = [sample_4624, sample_4625]
        db = Database(":memory:")

        try:
            pipeline = Pipeline(db)

            result = ingest_windows_security_events(pipeline, 2)

            self.assertEqual(result["collected"], 2)
            self.assertEqual(result["ingested"], 1)
            self.assertEqual(result["duplicates"], 0)
            self.assertEqual(result["ignored"], 1)
            self.assertEqual(result["errors"], [])

            events = db.list_events()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["event_type"], "login_failure")
        finally:
            db.close()

    @patch(
        "backend.ingestion.windows_security_collector.read_windows_security_events"
    )
    def test_repeated_collection_does_not_duplicate_events(self, mock_read):
        sample_4625 = make_security_xml(
            event_id="4625",
            logon_type="2",
        )
        mock_read.return_value = [sample_4625]

        db = Database(":memory:")

        try:
            pipeline = Pipeline(db)

            first = ingest_windows_security_events(pipeline, 1)
            second = ingest_windows_security_events(pipeline, 1)

            self.assertEqual(first["ingested"], 1)
            self.assertEqual(second["ingested"], 0)
            self.assertEqual(second["duplicates"], 1)
            self.assertEqual(len(db.list_events()), 1)
        finally:
            db.close()

    @patch(
        "backend.ingestion.windows_security_collector.read_windows_security_events"
    )
    def test_malformed_record_is_counted_as_error(self, mock_read):
        mock_read.return_value = ["<Event>invalid"]

        db = Database(":memory:")

        try:
            pipeline = Pipeline(db)
            result = ingest_windows_security_events(pipeline, 1)

            self.assertEqual(result["collected"], 1)
            self.assertEqual(result["ingested"], 0)
            self.assertEqual(result["errors"][0]["record"], 1)
        finally:
            db.close()

    @patch(
        "backend.ingestion.windows_security_collector.read_windows_security_events"
    )
    def test_windows_security_events_trigger_credential_compromise_alert(
        self, mock_read
    ):
        events = [
            make_security_xml(
                event_id="4625",
                logon_type="2",
                record_id="2001",
                timestamp="2026-11-21T10:00:00.0000000Z",
                source_ip="203.0.113.10",
            ),
            make_security_xml(
                event_id="4625",
                logon_type="2",
                record_id="2002",
                timestamp="2026-11-21T10:00:30.0000000Z",
                source_ip="203.0.113.10",
            ),
            make_security_xml(
                event_id="4625",
                logon_type="2",
                record_id="2003",
                timestamp="2026-11-21T10:01:00.0000000Z",
                source_ip="203.0.113.10",
            ),
            make_security_xml(
                event_id="4624",
                logon_type="2",
                record_id="2004",
                timestamp="2026-11-21T10:01:30.0000000Z",
                source_ip="203.0.113.10",
            ),
        ]

        mock_read.return_value = events

        db = Database(":memory:")

        try:
            pipeline = Pipeline(db)
            result = ingest_windows_security_events(pipeline, 4)

            self.assertEqual(result["collected"], 4)
            self.assertEqual(result["ingested"], 4)
            self.assertEqual(result["duplicates"], 0)
            self.assertEqual(result["ignored"], 0)
            self.assertEqual(result["errors"], [])

            alerts = db.alerts_for_rule("POSSIBLE_CREDENTIAL_COMPROMISE")

            self.assertGreaterEqual(len(alerts), 1)

            alert = alerts[0]

            self.assertEqual(
                alert["classification"],
                "possible_credential_compromise",
            )
            self.assertEqual(alert["severity"], "critical")
            self.assertEqual(len(alert["evidence"]), 4)

        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()

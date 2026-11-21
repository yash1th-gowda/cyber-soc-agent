import subprocess
from unittest.mock import patch

from backend.database.db import Database
from backend.pipeline import Pipeline
from backend.ingestion.windows_event_collector import (
    WindowsEventCollectionError,
    read_windows_system_events,
    ingest_windows_system_events,
)

import unittest

from backend.ingestion.windows_event_collector import (
    WindowsEventParseError,
    normalize_windows_event,
)


SAMPLE_XML = """\
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Kernel-Power'
              Guid='{331c3b3a-2005-44c2-ac5e-77220c37d6b4}'/>
    <EventID>105</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime='2026-11-21T18:52:12.3134246Z'/>
    <EventRecordID>66079</EventRecordID>
    <Channel>System</Channel>
    <Computer>Spectre</Computer>
  </System>
  <EventData>
    <Data Name='AcOnline'>true</Data>
    <Data Name='RemainingCapacity'>14980</Data>
    <Data Name='FullChargeCapacity'>73146</Data>
  </EventData>
</Event>
"""


class TestWindowsEventNormalizer(unittest.TestCase):

    def test_normalizes_system_event(self):
        event = normalize_windows_event(SAMPLE_XML)

        self.assertEqual(event["event_type"], "windows_system_event")
        self.assertEqual(event["severity"], "informational")
        self.assertEqual(event["hostname"], "Spectre")
        self.assertEqual(event["source"], "windows_event_log:System")

        raw = event["raw_event"]
        self.assertEqual(raw["windows_event_id"], "105")
        self.assertEqual(raw["record_id"], "66079")
        self.assertEqual(raw["provider"], "Microsoft-Windows-Kernel-Power")
        self.assertEqual(raw["event_data"]["AcOnline"], "true")
        self.assertEqual(raw["event_data"]["RemainingCapacity"], "14980")

    def test_event_id_is_deterministic(self):
        first = normalize_windows_event(SAMPLE_XML)
        second = normalize_windows_event(SAMPLE_XML)

        self.assertEqual(first["event_id"], second["event_id"])

    def test_preserves_original_xml(self):
        event = normalize_windows_event(SAMPLE_XML)

        self.assertEqual(event["raw_event"]["xml"], SAMPLE_XML)

    def test_invalid_xml_is_rejected(self):
        with self.assertRaises(WindowsEventParseError):
            normalize_windows_event("<Event>")

    def test_empty_input_is_rejected(self):
        with self.assertRaises(WindowsEventParseError):
            normalize_windows_event("")

    def test_missing_system_metadata_is_rejected(self):
        xml = """\
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
          <System>
            <EventID>105</EventID>
          </System>
        </Event>
        """
        with self.assertRaises(WindowsEventParseError):
            normalize_windows_event(xml)

    def test_different_record_ids_produce_different_event_ids(self):
        first = normalize_windows_event(SAMPLE_XML)

        changed_xml = SAMPLE_XML.replace(
            "<EventRecordID>66079</EventRecordID>",
            "<EventRecordID>66080</EventRecordID>",
        )
        second = normalize_windows_event(changed_xml)

        self.assertNotEqual(first["event_id"], second["event_id"])


    def test_empty_event_data_is_supported(self):
        xml = SAMPLE_XML

        start = xml.index("<EventData>")
        end = xml.index("</EventData>") + len("</EventData>")
        xml = xml[:start] + "<EventData></EventData>" + xml[end:]

        event = normalize_windows_event(xml)

        self.assertEqual(event["raw_event"]["event_data"], {})



class TestWindowsEventReader(unittest.TestCase):

    @patch("backend.ingestion.windows_event_collector.subprocess.run")
    def test_reads_xml_records_from_powershell(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout='["<Event>one</Event>", "<Event>two</Event>"]',
            stderr="",
        )

        records = read_windows_system_events(2)

        self.assertEqual(len(records), 2)
        self.assertEqual(records[0], "<Event>one</Event>")
        self.assertEqual(records[1], "<Event>two</Event>")
        self.assertEqual(mock_run.call_args.kwargs["timeout"], 30)

    def test_rejects_invalid_event_limits(self):
        for value in (0, -1, 1001, True, "3"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    read_windows_system_events(value)

    @patch("backend.ingestion.windows_event_collector.subprocess.run")
    def test_handles_powershell_failure(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr="Access denied",
        )

        with self.assertRaises(WindowsEventCollectionError):
            read_windows_system_events(3)

    @patch("backend.ingestion.windows_event_collector.subprocess.run")
    def test_handles_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd="powershell.exe",
            timeout=30,
        )

        with self.assertRaises(WindowsEventCollectionError):
            read_windows_system_events(3)

    @patch("backend.ingestion.windows_event_collector.subprocess.run")
    def test_rejects_invalid_powershell_json(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="not-json",
            stderr="",
        )

        with self.assertRaises(WindowsEventCollectionError):
            read_windows_system_events(3)

    @patch("backend.ingestion.windows_event_collector.subprocess.run")
    def test_rejects_non_array_powershell_result(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout='"<Event/>"',
            stderr="",
        )

        with self.assertRaises(WindowsEventCollectionError):
            read_windows_system_events(3)

    @patch("backend.ingestion.windows_event_collector.subprocess.run")
    def test_empty_collection_returns_empty_list(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="[]",
            stderr="",
        )

        self.assertEqual(read_windows_system_events(3), [])


class TestWindowsEventIngestion(unittest.TestCase):

    @patch("backend.ingestion.windows_event_collector.read_windows_system_events")
    def test_repeated_collection_does_not_duplicate_database_events(self, mock_read):
        mock_read.return_value = [SAMPLE_XML]

        db = Database(":memory:")
        try:
            pipeline = Pipeline(db)

            first = ingest_windows_system_events(pipeline, 1)
            second = ingest_windows_system_events(pipeline, 1)

            self.assertEqual(first["ingested"], 1)
            self.assertEqual(first["duplicates"], 0)
            self.assertEqual(second["ingested"], 0)
            self.assertEqual(second["duplicates"], 1)
            self.assertEqual(len(db.list_events()), 1)
        finally:
            db.close()

if __name__ == "__main__":
    unittest.main()
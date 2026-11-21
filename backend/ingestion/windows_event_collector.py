"""Read-only Windows Event Log XML normalization."""
from __future__ import annotations

import hashlib
import json
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime

from backend.models.schemas import ValidationError


EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


class WindowsEventParseError(ValueError):
    """Raised when a Windows event XML record cannot be normalized."""


def _text(parent: ET.Element, path: str) -> str | None:
    element = parent.find(path)
    if element is None or element.text is None:
        return None
    return element.text.strip()


def normalize_windows_event(xml_text: str) -> dict:
    """Convert one Windows Event XML record into the SOC event schema."""
    if not isinstance(xml_text, str) or not xml_text.strip():
        raise WindowsEventParseError("Event XML must be a non-empty string")

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise WindowsEventParseError("Invalid Windows Event XML") from exc

    system = root.find(f"{EVENT_NS}System")
    if system is None:
        raise WindowsEventParseError("Missing System element")

    provider_element = system.find(f"{EVENT_NS}Provider")
    time_element = system.find(f"{EVENT_NS}TimeCreated")

    provider = provider_element.get("Name") if provider_element is not None else None
    time_created = time_element.get("SystemTime") if time_element is not None else None
    provider_guid = (
        provider_element.get("Guid") if provider_element is not None else None
    )

    event_id = _text(system, f"{EVENT_NS}EventID")
    record_id = _text(system, f"{EVENT_NS}EventRecordID")
    channel = _text(system, f"{EVENT_NS}Channel")
    computer = _text(system, f"{EVENT_NS}Computer")

    if not all((provider, time_created, event_id, record_id, channel, computer)):
        raise WindowsEventParseError("Windows event is missing required system metadata")

    try:
        timestamp = datetime.fromisoformat(
            time_created.replace("Z", "+00:00")
        ).isoformat()
    except ValueError as exc:
        raise WindowsEventParseError("Invalid event timestamp") from exc

    identity = json.dumps(
        [
            computer,
            channel,
            record_id,
            provider,
            provider_guid,
            event_id,
            time_created,
        ],
        separators=(",", ":"),
    )
    stable_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    normalized_id = f"WINEVT-{stable_id}"
    event_data = {}
    event_data_element = root.find(f"{EVENT_NS}EventData")
    if event_data_element is not None:
        for item in event_data_element.findall(f"{EVENT_NS}Data"):
            name = item.get("Name") or f"Field{len(event_data) + 1}"
            value = item.text.strip() if item.text else ""

            # Preserve repeated field names rather than silently losing values.
            if name in event_data:
                if not isinstance(event_data[name], list):
                    event_data[name] = [event_data[name]]
                event_data[name].append(value)
            else:
                event_data[name] = value

    level = _text(system, f"{EVENT_NS}Level")

    return {
        "event_id": normalized_id,
        "timestamp": timestamp,
        "source": f"windows_event_log:{channel}",
        "event_type": "windows_system_event",
        "severity": "informational",
        "hostname": computer,
        "message": f"Windows event {event_id} from {provider}",
        "raw_event": {
            "provider": provider,
            "provider_guid": provider_guid,
            "windows_event_id": event_id,
            "record_id": record_id,
            "channel": channel,
            "computer": computer,
            "level": level,
            "event_data": event_data,
            "xml": xml_text,
        },
        "indicators": [],
    }


class WindowsEventCollectionError(RuntimeError):
    """Raised when Windows Event Log collection fails."""


def read_windows_system_events(max_events: int = 100) -> list[str]:
    """Read a bounded batch of XML records from the Windows System channel.

    This function only reads existing events. It does not modify Windows logs.
    """
    if isinstance(max_events, bool) or not isinstance(max_events, int):
        raise ValueError("max_events must be an integer")

    if not 1 <= max_events <= 1000:
        raise ValueError("max_events must be between 1 and 1000")

    script = f"""
$ErrorActionPreference = 'Stop'
$records = @(
    Get-WinEvent -LogName 'System' -MaxEvents {max_events} |
    ForEach-Object {{ $_.ToXml() }}
)
ConvertTo-Json -InputObject $records -Compress
"""

    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise WindowsEventCollectionError(
            "Windows Event Log collection timed out"
        ) from exc
    except OSError as exc:
        raise WindowsEventCollectionError(
            "Could not start Windows PowerShell"
        ) from exc

    if result.returncode != 0:
        detail = result.stderr.strip() or "Unknown PowerShell error"
        raise WindowsEventCollectionError(detail)

    try:
        records = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise WindowsEventCollectionError(
            "PowerShell returned invalid JSON"
        ) from exc

    if not isinstance(records, list):
        raise WindowsEventCollectionError(
            "Expected PowerShell to return a JSON array"
        )

    if not all(isinstance(record, str) for record in records):
        raise WindowsEventCollectionError(
            "PowerShell returned an invalid event record"
        )

    return records


def ingest_windows_system_events(pipeline, max_events: int = 100) -> dict:
    """Collect Windows System events and ingest them through the SOC pipeline."""
    xml_records = read_windows_system_events(max_events)

    result = {
        "collected": len(xml_records),
        "ingested": 0,
        "duplicates": 0,
        "alerts": 0,
        "errors": [],
    }

    for index, xml_record in enumerate(xml_records, start=1):
        try:
            event = normalize_windows_event(xml_record)
            outcome = pipeline.ingest_event(event)

            if outcome.get("duplicate") == "identical":
                result["duplicates"] += 1
            else:
                result["ingested"] += 1

            result["alerts"] += len(outcome.get("alerts", []))

        except (WindowsEventParseError, ValidationError) as exc:
            result["errors"].append({
                "record": index,
                "error": str(exc),
            })

    return result

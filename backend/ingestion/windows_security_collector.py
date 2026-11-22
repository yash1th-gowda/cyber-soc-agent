
"""Read-only Windows Security Event Log XML normalization."""
from __future__ import annotations
import subprocess
import hashlib
import json
import xml.etree.ElementTree as ET
from datetime import datetime

from backend.models.schemas import ValidationError


EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# Initial supported logon types.
SUPPORTED_LOGON_TYPES = {2, 3, 10}

SUPPORTED_EVENT_IDS = {"4624", "4625"}


class WindowsSecurityEventParseError(ValueError):
    """Raised when a Windows Security event cannot be normalized."""


def _text(parent: ET.Element, path: str) -> str | None:
    element = parent.find(path)

    if element is None or element.text is None:
        return None

    return element.text.strip()


def _event_data(root: ET.Element) -> dict:
    """Extract EventData while preserving repeated field names."""
    data = {}
    event_data_element = root.find(f"{EVENT_NS}EventData")

    if event_data_element is None:
        return data

    for item in event_data_element.findall(f"{EVENT_NS}Data"):
        name = item.get("Name") or f"Field{len(data) + 1}"
        value = item.text.strip() if item.text else ""

        if name in data:
            if not isinstance(data[name], list):
                data[name] = [data[name]]

            data[name].append(value)
        else:
            data[name] = value

    return data


def normalize_windows_security_event(xml_text: str) -> dict | None:
    """Normalize supported Windows Security logon events.

    Returns:
        A normalized SecurityEvent dictionary for supported events.
        None when the event is not a supported logon type or event ID.
    """
    if not isinstance(xml_text, str) or not xml_text.strip():
        raise WindowsSecurityEventParseError(
            "Event XML must be a non-empty string"
        )

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise WindowsSecurityEventParseError(
            "Invalid Windows Security Event XML"
        ) from exc

    system = root.find(f"{EVENT_NS}System")

    if system is None:
        raise WindowsSecurityEventParseError(
            "Missing System element"
        )

    provider_element = system.find(f"{EVENT_NS}Provider")
    time_element = system.find(f"{EVENT_NS}TimeCreated")

    provider = (
        provider_element.get("Name")
        if provider_element is not None
        else None
    )

    provider_guid = (
        provider_element.get("Guid")
        if provider_element is not None
        else None
    )

    time_created = (
        time_element.get("SystemTime")
        if time_element is not None
        else None
    )

    event_id = _text(system, f"{EVENT_NS}EventID")
    record_id = _text(system, f"{EVENT_NS}EventRecordID")
    channel = _text(system, f"{EVENT_NS}Channel")
    computer = _text(system, f"{EVENT_NS}Computer")

    if not all((
        provider,
        time_created,
        event_id,
        record_id,
        channel,
        computer,
    )):
        raise WindowsSecurityEventParseError(
            "Security event is missing required System metadata"
        )

    # Only process Windows Security logon events.
    if channel != "Security":
        raise WindowsSecurityEventParseError(
            "Expected a Windows Security channel event"
        )

    if provider != "Microsoft-Windows-Security-Auditing":
        raise WindowsSecurityEventParseError(
            "Unexpected Windows Security event provider"
        )

    # Other Security event IDs are outside this collector's scope.
    if event_id not in SUPPORTED_EVENT_IDS:
        return None

    try:
        timestamp = datetime.fromisoformat(
            time_created.replace("Z", "+00:00")
        ).isoformat()
    except ValueError as exc:
        raise WindowsSecurityEventParseError(
            "Invalid event timestamp"
        ) from exc

    event_data = _event_data(root)

    logon_type_raw = event_data.get("LogonType")

    if logon_type_raw is None:
        raise WindowsSecurityEventParseError(
            "Logon event is missing LogonType"
        )

    try:
        logon_type = int(logon_type_raw)
    except (TypeError, ValueError) as exc:
        raise WindowsSecurityEventParseError(
            "Invalid LogonType value"
        ) from exc

    # Ignore service, batch, unlock, and other unsupported logon types.
    if logon_type not in SUPPORTED_LOGON_TYPES:
        return None

    if event_id == "4624":
        normalized_event_type = "login_success"
        message = (
            f"Windows successful logon for "
            f"{event_data.get('TargetUserName', 'unknown user')}"
        )
    else:
        normalized_event_type = "login_failure"
        message = (
            f"Windows failed logon for "
            f"{event_data.get('TargetUserName', 'unknown user')}"
        )

    username = event_data.get("TargetUserName")
    source_ip = event_data.get("IpAddress")
    process = event_data.get("ProcessName")

    # Windows uses '-' when these values are unavailable.
    if not username or username == "-":
        username = None

    if not source_ip or source_ip == "-":
        source_ip = None

    if not process or process == "-":
        process = None

    # Stable identity: same Windows record produces the same event ID.
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

    stable_id = hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()

    normalized_id = f"WINEVT-{stable_id}"

    return {
        "event_id": normalized_id,
        "timestamp": timestamp,
        "source": "windows_event_log:Security",
        "event_type": normalized_event_type,
        "severity": "informational",
        "source_ip": source_ip,
        "username": username,
        "hostname": computer,
        "process": process,
        "message": message,
        "raw_event": {
            "provider": provider,
            "provider_guid": provider_guid,
            "windows_event_id": event_id,
            "record_id": record_id,
            "channel": channel,
            "computer": computer,
            "logon_type": logon_type,
            "event_data": event_data,
            "xml": xml_text,
        },
        "indicators": [],
    }


class WindowsSecurityEventCollectionError(RuntimeError):
    """Raised when Windows Security Event Log collection fails."""


def read_windows_security_events(max_events: int = 100) -> list[str]:
    """Read a bounded batch of 4624 and 4625 XML records.

    The function is read-only and does not change Windows audit settings.
    """
    if isinstance(max_events, bool) or not isinstance(max_events, int):
        raise ValueError("max_events must be an integer")

    if not 1 <= max_events <= 1000:
        raise ValueError("max_events must be between 1 and 1000")

    script = f"""
$ErrorActionPreference = 'Stop'
$records = @(
    Get-WinEvent -FilterHashtable @{{
        LogName = 'Security'
        Id = 4624, 4625
    }} -MaxEvents {max_events} |
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
        raise WindowsSecurityEventCollectionError(
            "Windows Security Event Log collection timed out"
        ) from exc
    except OSError as exc:
        raise WindowsSecurityEventCollectionError(
            "Could not start Windows PowerShell"
        ) from exc

    if result.returncode != 0:
        detail = result.stderr.strip() or "Unknown PowerShell error"
        raise WindowsSecurityEventCollectionError(detail)

    try:
        records = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise WindowsSecurityEventCollectionError(
            "PowerShell returned invalid JSON"
        ) from exc

    if not isinstance(records, list):
        raise WindowsSecurityEventCollectionError(
            "Expected PowerShell to return a JSON array"
        )

    if not all(isinstance(record, str) for record in records):
        raise WindowsSecurityEventCollectionError(
            "PowerShell returned an invalid event record"
        )

    return records


def ingest_windows_security_events(pipeline, max_events: int = 100) -> dict:
    """Collect, normalize, filter, and ingest Windows Security events."""
    xml_records = read_windows_security_events(max_events)

    result = {
        "collected": len(xml_records),
        "ingested": 0,
        "duplicates": 0,
        "ignored": 0,
        "alerts": 0,
        "errors": [],
    }

    for index, xml_record in enumerate(xml_records, start=1):
        try:
            event = normalize_windows_security_event(xml_record)

            if event is None:
                result["ignored"] += 1
                continue

            outcome = pipeline.ingest_event(event)

            if outcome.get("duplicate") == "identical":
                result["duplicates"] += 1
            else:
                result["ingested"] += 1

            result["alerts"] += len(outcome.get("alerts", []))

        except (WindowsSecurityEventParseError, ValidationError) as exc:
            result["errors"].append({
                "record": index,
                "error": str(exc),
            })

    return result

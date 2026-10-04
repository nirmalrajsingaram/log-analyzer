"""
Syslog Parser Module
Parses RFC 3164 and RFC 5424 syslog messages into structured data.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# Syslog severity levels
SEVERITY = {
    0: "EMERGENCY",
    1: "ALERT",
    2: "CRITICAL",
    3: "ERROR",
    4: "WARNING",
    5: "NOTICE",
    6: "INFO",
    7: "DEBUG",
}

# Syslog facility codes
FACILITY = {
    0: "kern",
    1: "user",
    2: "mail",
    3: "daemon",
    4: "auth",
    5: "syslog",
    6: "lpr",
    7: "news",
    8: "uucp",
    9: "cron",
    10: "authpriv",
    11: "ftp",
    16: "local0",
    17: "local1",
    18: "local2",
    19: "local3",
    20: "local4",
    21: "local5",
    22: "local6",
    23: "local7",
}

# RFC 3164 pattern: <PRI>Mon DD HH:MM:SS hostname process[pid]: message
RFC3164_PATTERN = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

# RFC 5424 pattern: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
RFC5424_PATTERN = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<appname>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<structured_data>\S+)\s*"
    r"(?P<message>.*)$"
)

# Plain fallback: any line with a timestamp
PLAIN_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)


@dataclass
class SyslogEntry:
    raw: str
    timestamp: Optional[datetime] = None
    hostname: str = "unknown"
    process: str = "unknown"
    pid: Optional[int] = None
    facility: str = "unknown"
    severity: str = "unknown"
    severity_level: int = -1
    message: str = ""
    format: str = "unknown"
    extra: dict = field(default_factory=dict)

    def is_error(self) -> bool:
        return self.severity_level in (0, 1, 2, 3)

    def is_warning(self) -> bool:
        return self.severity_level == 4

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "hostname": self.hostname,
            "process": self.process,
            "pid": self.pid,
            "facility": self.facility,
            "severity": self.severity,
            "severity_level": self.severity_level,
            "message": self.message,
            "format": self.format,
            "raw": self.raw,
        }


def _decode_priority(pri: int):
    """Decode syslog PRI value into facility and severity."""
    facility_code = pri >> 3
    severity_code = pri & 0x07
    facility_name = FACILITY.get(facility_code, f"facility{facility_code}")
    severity_name = SEVERITY.get(severity_code, "UNKNOWN")
    return facility_name, severity_name, severity_code


def _parse_timestamp_3164(ts_str: str) -> Optional[datetime]:
    """Parse RFC 3164 timestamp (no year — assume current year)."""
    current_year = datetime.now().year
    for fmt in ("%b %d %H:%M:%S", "%b  %d %H:%M:%S"):
        try:
            dt = datetime.strptime(f"{current_year} {ts_str}", f"%Y {fmt}")
            return dt
        except ValueError:
            continue
    return None


def _parse_timestamp_5424(ts_str: str) -> Optional[datetime]:
    """Parse RFC 5424 ISO 8601 timestamp."""
    if ts_str == "-":
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
    ):
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None


def parse_line(line: str) -> SyslogEntry:
    """Parse a single syslog line into a SyslogEntry."""
    line = line.strip()
    entry = SyslogEntry(raw=line)

    # Try RFC 5424
    m = RFC5424_PATTERN.match(line)
    if m:
        pri = int(m.group("pri"))
        facility, severity, sev_level = _decode_priority(pri)
        entry.format = "RFC5424"
        entry.timestamp = _parse_timestamp_5424(m.group("timestamp"))
        entry.hostname = m.group("hostname")
        entry.process = m.group("appname")
        pid_str = m.group("procid")
        entry.pid = int(pid_str) if pid_str.isdigit() else None
        entry.facility = facility
        entry.severity = severity
        entry.severity_level = sev_level
        entry.message = m.group("message")
        entry.extra["msgid"] = m.group("msgid")
        entry.extra["structured_data"] = m.group("structured_data")
        return entry

    # Try RFC 3164
    m = RFC3164_PATTERN.match(line)
    if m:
        pri = int(m.group("pri"))
        facility, severity, sev_level = _decode_priority(pri)
        entry.format = "RFC3164"
        entry.timestamp = _parse_timestamp_3164(m.group("timestamp"))
        entry.hostname = m.group("hostname")
        entry.process = m.group("process")
        pid_str = m.group("pid")
        entry.pid = int(pid_str) if pid_str else None
        entry.facility = facility
        entry.severity = severity
        entry.severity_level = sev_level
        entry.message = m.group("message")
        return entry

    # Try plain syslog (no PRI)
    m = PLAIN_PATTERN.match(line)
    if m:
        entry.format = "PLAIN"
        entry.timestamp = _parse_timestamp_3164(m.group("timestamp"))
        entry.hostname = m.group("hostname")
        entry.process = m.group("process")
        pid_str = m.group("pid")
        entry.pid = int(pid_str) if pid_str else None
        entry.message = m.group("message")
        entry.severity = "UNKNOWN"
        return entry

    # Unparseable — store raw
    entry.format = "UNPARSEABLE"
    entry.message = line
    return entry

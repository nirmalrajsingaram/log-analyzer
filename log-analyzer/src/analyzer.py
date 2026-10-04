"""
Log Analyzer Module
Aggregates and analyzes parsed syslog entries to produce statistics and alerts.
"""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from .parser import SyslogEntry


@dataclass
class AnalysisResult:
    total_entries: int = 0
    by_severity: dict = field(default_factory=dict)
    by_facility: dict = field(default_factory=dict)
    by_hostname: dict = field(default_factory=dict)
    by_process: dict = field(default_factory=dict)
    by_format: dict = field(default_factory=dict)
    error_entries: List[SyslogEntry] = field(default_factory=list)
    warning_entries: List[SyslogEntry] = field(default_factory=list)
    unparseable_count: int = 0
    time_range: dict = field(default_factory=dict)
    top_processes: List[tuple] = field(default_factory=list)
    top_hostnames: List[tuple] = field(default_factory=list)
    alerts: List[str] = field(default_factory=list)


class LogAnalyzer:
    def __init__(self, config: dict):
        self.config = config
        self.alert_rules = config.get("alert_rules", {})

    def analyze(self, entries: List[SyslogEntry]) -> AnalysisResult:
        result = AnalysisResult()
        result.total_entries = len(entries)

        severity_counter = Counter()
        facility_counter = Counter()
        hostname_counter = Counter()
        process_counter = Counter()
        format_counter = Counter()
        timestamps = []

        for entry in entries:
            severity_counter[entry.severity] += 1
            facility_counter[entry.facility] += 1
            hostname_counter[entry.hostname] += 1
            process_counter[entry.process] += 1
            format_counter[entry.format] += 1

            if entry.timestamp:
                timestamps.append(entry.timestamp)

            if entry.is_error():
                result.error_entries.append(entry)

            if entry.is_warning():
                result.warning_entries.append(entry)

            if entry.format == "UNPARSEABLE":
                result.unparseable_count += 1

        result.by_severity = dict(severity_counter.most_common())
        result.by_facility = dict(facility_counter.most_common())
        result.by_hostname = dict(hostname_counter.most_common())
        result.by_process = dict(process_counter.most_common())
        result.by_format = dict(format_counter.most_common())
        result.top_processes = process_counter.most_common(10)
        result.top_hostnames = hostname_counter.most_common(10)

        if timestamps:
            result.time_range = {
                "start": min(timestamps).isoformat(),
                "end": max(timestamps).isoformat(),
            }

        result.alerts = self._check_alerts(result)
        return result

    def _check_alerts(self, result: AnalysisResult) -> List[str]:
        alerts = []
        max_errors = self.alert_rules.get("max_errors", 100)
        max_warnings = self.alert_rules.get("max_warnings", 500)
        max_unparseable_pct = self.alert_rules.get("max_unparseable_pct", 10)

        error_count = len(result.error_entries)
        warning_count = len(result.warning_entries)

        if error_count > max_errors:
            alerts.append(
                f"HIGH ERROR RATE: {error_count} error-level entries "
                f"(threshold: {max_errors})"
            )

        if warning_count > max_warnings:
            alerts.append(
                f"HIGH WARNING RATE: {warning_count} warning entries "
                f"(threshold: {max_warnings})"
            )

        if result.total_entries > 0:
            unparseable_pct = (result.unparseable_count / result.total_entries) * 100
            if unparseable_pct > max_unparseable_pct:
                alerts.append(
                    f"HIGH UNPARSEABLE RATE: {unparseable_pct:.1f}% of entries "
                    f"could not be parsed (threshold: {max_unparseable_pct}%)"
                )

        # Alert on burst from a single host
        burst_threshold = self.alert_rules.get("host_burst_threshold", 1000)
        for host, count in result.top_hostnames:
            if count > burst_threshold:
                alerts.append(
                    f"LOG BURST: Host '{host}' produced {count} entries "
                    f"(threshold: {burst_threshold})"
                )

        return alerts

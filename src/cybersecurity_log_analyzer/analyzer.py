"""Parsing and aggregation for synthetic authentication logs."""

from dataclasses import dataclass
from datetime import datetime
from collections import Counter
import ipaddress
import re
from typing import Iterable


@dataclass(frozen=True)
class LogEntry:
    """One validated authentication event."""

    timestamp: datetime
    event: str
    username: str
    ip: str


@dataclass(frozen=True)
class AnalysisReport:
    """Deterministic summary of the records found in an input."""

    total_entries: int
    failed_attempts: int
    successful_logins: int
    failed_by_ip: dict[str, int]
    suspicious_ips: list[str]
    malformed_lines: int


_LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?P<event>login_failed|login_success)\s+"
    r"user=(?P<username>\S+)\s+"
    r"ip=(?P<ip>\S+)$"
)


def parse_log_line(line: str) -> LogEntry | None:
    """Parse one authentication log line, returning ``None`` if invalid."""

    match = _LOG_PATTERN.fullmatch(line.strip())
    if match is None:
        return None

    try:
        timestamp = datetime.fromisoformat(
            match.group("timestamp").replace("Z", "+00:00")
        )
        ip = ipaddress.ip_address(match.group("ip"))
    except ValueError:
        return None

    if timestamp.tzinfo is None:
        return None

    return LogEntry(
        timestamp=timestamp,
        event=match.group("event"),
        username=match.group("username"),
        ip=str(ip),
    )


def analyze_lines(
    lines: Iterable[str], suspicious_threshold: int = 3
) -> AnalysisReport:
    """Aggregate valid authentication events and flag repeated failures."""

    if suspicious_threshold < 1:
        raise ValueError("suspicious_threshold must be at least 1")

    total_entries = 0
    failed_attempts = 0
    successful_logins = 0
    malformed_lines = 0
    failed_by_ip: Counter[str] = Counter()

    for line in lines:
        entry = parse_log_line(line)
        if entry is None:
            malformed_lines += 1
            continue

        total_entries += 1
        if entry.event == "login_failed":
            failed_attempts += 1
            failed_by_ip[entry.ip] += 1
        else:
            successful_logins += 1

    suspicious_ips = sorted(
        (ip for ip, count in failed_by_ip.items() if count >= suspicious_threshold),
        key=ipaddress.ip_address,
    )

    return AnalysisReport(
        total_entries=total_entries,
        failed_attempts=failed_attempts,
        successful_logins=successful_logins,
        failed_by_ip=dict(sorted(failed_by_ip.items())),
        suspicious_ips=suspicious_ips,
        malformed_lines=malformed_lines,
    )

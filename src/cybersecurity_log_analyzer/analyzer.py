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
    lines: Iterable[str]�\�X�[�\���\���[�HHO�[�[\�\ԙ\ܝ�����Y�ܙY�]H�[Y]][�X�][ۈ]�[��[��Y��\X]Y�Z[\�\ˈ�����Y��\�X�[�\���\��N���Z\�H�[YQ\��܊��\�X�[�\���\��]\��H]X\�H�B���[�[��Y\�H��Z[Y�][\�H��X��\�ٝ[���[��H�X[�ܛYY�[�\�H��Z[Y؞W�\���[�\����HH��[�\�
B���܈[�H[�[�\΂�[��HH\��W����[�J[�JB�Y�[��H\��ۙN��X[�ܛYY�[�\�
�HB��۝[�YB���[�[��Y\�
�HB�Y�[��K�]�[�OH���[�٘Z[Y����Z[Y�][\�
�HB��Z[Y؞W�\�[��K�\H
�HB�[�N���X��\�ٝ[���[��
�HB���\�X�[�\��\�H�ܝY
�
\�܈\��[�[��Z[Y؞W�\�][\�
HY���[��H�\�X��\���\��
K��^OZ\Y�\�˚\�Y�\���
B���]\��[�[\�\ԙ\ܝ
��[�[��Y\�]�[�[��Y\���Z[Y�][\�Y�Z[Y�][\���X��\�ٝ[���[��\�X��\�ٝ[���[����Z[Y؞W�\YX�
�ܝY
�Z[Y؞W�\�][\�
JJK��\�X�[�\��\�\�\�X�[�\��\��X[�ܙY�[�\�[X[�ܛYY�[�\��
B

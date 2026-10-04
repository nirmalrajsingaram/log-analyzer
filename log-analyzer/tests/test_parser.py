"""Basic tests for the syslog parser."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.parser import parse_line


def test_rfc3164():
    line = "<34>Oct  4 10:23:45 myhost kernel: Out of memory: Kill process 1234"
    entry = parse_line(line)
    assert entry.format == "RFC3164"
    assert entry.hostname == "myhost"
    assert entry.process == "kernel"
    assert entry.severity == "CRITICAL"
    assert entry.facility == "auth"
    assert "Out of memory" in entry.message


def test_rfc5424():
    line = (
        "<165>1 2026-10-04T10:23:45.000Z myhost myapp 1234 ID47 - "
        "An application error occurred"
    )
    entry = parse_line(line)
    assert entry.format == "RFC5424"
    assert entry.hostname == "myhost"
    assert entry.process == "myapp"
    assert entry.pid == 1234
    assert "application error" in entry.message


def test_unparseable():
    line = "this is just random garbage text"
    entry = parse_line(line)
    assert entry.format == "UNPARSEABLE"
    assert entry.message == line


def test_is_error():
    line = "<3>Oct  4 10:23:45 myhost sshd[999]: Failed password for root"
    entry = parse_line(line)
    assert entry.is_error()


def test_is_warning():
    line = "<4>Oct  4 10:23:45 myhost sshd[999]: Possible attack detected"
    entry = parse_line(line)
    # pri=4 → facility=0 (kern), severity=4 (WARNING)
    assert entry.is_warning()

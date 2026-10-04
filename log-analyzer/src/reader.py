"""
Log Reader Module
Handles reading syslog from files, stdin, and live UDP/TCP syslog streams.
"""

import gzip
import logging
import os
import socket
import socketserver
import sys
import threading
from pathlib import Path
from queue import Queue
from typing import Callable, Iterator, Optional

logger = logging.getLogger(__name__)


def read_file(path: str) -> Iterator[str]:
    """Read log lines from a plain or gzip-compressed file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    open_fn = gzip.open if path.endswith(".gz") else open
    encoding = "utf-8" if not path.endswith(".gz") else None
    kwargs = {"mode": "rt", "encoding": "utf-8", "errors": "replace"} if not path.endswith(".gz") else {"mode": "rt", "encoding": "utf-8", "errors": "replace"}

    with open_fn(path, **kwargs) as f:
        for line in f:
            yield line.rstrip("\n")


def read_stdin() -> Iterator[str]:
    """Read log lines from standard input."""
    for line in sys.stdin:
        yield line.rstrip("\n")


def read_directory(path: str, pattern: str = "*.log") -> Iterator[str]:
    """Read all matching log files from a directory."""
    p = Path(path)
    files = sorted(p.glob(pattern))
    if not files:
        logger.warning(f"No files matching '{pattern}' found in {path}")
    for f in files:
        logger.info(f"Reading: {f}")
        yield from read_file(str(f))


class SyslogUDPHandler(socketserver.BaseRequestHandler):
    """UDP handler that pushes received syslog messages into a queue."""

    def handle(self):
        data = bytes.decode(self.request[0].strip())
        self.server.queue.put(data)


class SyslogServer:
    """Simple UDP/TCP syslog server for live log ingestion."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 514,
        protocol: str = "udp",
    ):
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.queue: Queue = Queue()
        self._server = None
        self._thread = None

    def start(self):
        if self.protocol == "udp":
            server = socketserver.UDPServer((self.host, self.port), SyslogUDPHandler)
            server.queue = self.queue
            self._server = server
            self._thread = threading.Thread(target=server.serve_forever, daemon=True)
            self._thread.start()
            logger.info(f"UDP syslog server listening on {self.host}:{self.port}")
        else:
            raise NotImplementedError("TCP syslog server not yet implemented")

    def stop(self):
        if self._server:
            self._server.shutdown()
            logger.info("Syslog server stopped")

    def messages(self) -> Iterator[str]:
        """Yield messages as they arrive."""
        while True:
            yield self.queue.get()

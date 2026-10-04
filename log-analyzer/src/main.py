"""
Log Analyzer — Entry Point
Usage:
  python -m src.main [OPTIONS]
  python -m src.main --file /var/log/syslog
  python -m src.main --stdin
  python -m src.main --dir /var/log --pattern "*.log"
  python -m src.main --listen --port 514
"""

import argparse
import logging
import os
import sys
import yaml

from .analyzer import LogAnalyzer
from .parser import parse_line
from .reader import read_file, read_stdin, read_directory, SyslogServer
from .reporter import Reporter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("log-analyzer")


def load_config(path: str) -> dict:
    if not os.path.exists(path):
        logger.warning(f"Config file not found at {path}, using defaults.")
        return {}
    with open(path, "r") as f:
        return yaml.safe_load(f) or {}


def run(args: argparse.Namespace, config: dict):
    analyzer = LogAnalyzer(config)
    output_dir = config.get("output_dir", "/reports")
    reporter = Reporter(output_dir=output_dir)

    entries = []

    if args.listen:
        host = config.get("server", {}).get("host", "0.0.0.0")
        port = args.port or config.get("server", {}).get("port", 514)
        logger.info(f"Starting live UDP syslog listener on {host}:{port}")
        server = SyslogServer(host=host, port=port)
        server.start()
        batch_size = config.get("batch_size", 1000)
        try:
            count = 0
            for raw in server.messages():
                entries.append(parse_line(raw))
                count += 1
                if count % batch_size == 0:
                    logger.info(f"Processed {count} entries so far...")
        except KeyboardInterrupt:
            logger.info("Shutting down listener...")
            server.stop()
    else:
        if args.stdin:
            logger.info("Reading from stdin...")
            lines = read_stdin()
        elif args.file:
            logger.info(f"Reading file: {args.file}")
            lines = read_file(args.file)
        elif args.dir:
            pattern = args.pattern or config.get("file_pattern", "*.log")
            logger.info(f"Reading directory: {args.dir} (pattern: {pattern})")
            lines = read_directory(args.dir, pattern=pattern)
        else:
            # Default: try /var/log/syslog or /var/log/messages
            defaults = ["/var/log/syslog", "/var/log/messages", "/var/log/system.log"]
            for path in defaults:
                if os.path.exists(path):
                    logger.info(f"Auto-detected log file: {path}")
                    lines = read_file(path)
                    break
            else:
                logger.error("No log source specified and no default syslog file found.")
                logger.error("Use --file, --stdin, --dir, or --listen.")
                sys.exit(1)

        for i, line in enumerate(lines):
            if line.strip():
                entries.append(parse_line(line))
            if (i + 1) % 10000 == 0:
                logger.info(f"Parsed {i + 1:,} lines...")

    logger.info(f"Total entries parsed: {len(entries):,}")

    result = analyzer.analyze(entries)

    # Always print summary to stdout
    reporter.print_summary(result)

    # Save reports based on config
    output_formats = config.get("output_formats", ["json", "html"])
    if "json" in output_formats:
        path = reporter.save_json(result)
        logger.info(f"JSON report: {path}")
    if "html" in output_formats:
        path = reporter.save_html(result)
        logger.info(f"HTML report: {path}")

    # Exit non-zero if there are alerts
    if result.alerts:
        logger.warning(f"{len(result.alerts)} alert(s) triggered.")
        sys.exit(2)


def main():
    parser = argparse.ArgumentParser(
        description="Syslog Log Analyzer — parse, analyze, and report on syslog data."
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--file", "-f", help="Path to a syslog file (supports .gz)")
    source.add_argument("--stdin", "-s", action="store_true", help="Read from stdin")
    source.add_argument("--dir", "-d", help="Directory containing log files")
    source.add_argument("--listen", "-l", action="store_true", help="Start UDP syslog listener")

    parser.add_argument("--pattern", "-p", default="*.log", help="File glob pattern (with --dir)")
    parser.add_argument("--port", type=int, help="UDP port for --listen mode (default: 514)")
    parser.add_argument(
        "--config", "-c",
        default=os.environ.get("CONFIG_PATH", "/config/config.yaml"),
        help="Path to YAML config file",
    )

    args = parser.parse_args()
    config = load_config(args.config)
    run(args, config)


if __name__ == "__main__":
    main()

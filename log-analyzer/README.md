# Syslog Log Analyzer

A lightweight, containerized syslog analyzer that parses **RFC 3164** and **RFC 5424** syslog messages, aggregates statistics, triggers configurable alerts, and outputs **JSON** + **HTML** reports.

---

## Features

| Feature | Details |
|---|---|
| **Parsing** | RFC 3164, RFC 5424, plain syslog, gzip-compressed files |
| **Analysis** | Severity / facility / host / process breakdown, top-N rankings |
| **Alerts** | Configurable thresholds for error rate, warning rate, log bursts |
| **Output** | Console summary, JSON report, styled HTML dashboard |
| **Input modes** | File, directory, stdin, live UDP syslog listener |
| **Docker** | Multi-stage build, non-root user, three Compose profiles |

---

## Project Structure

```
log-analyzer/
├── src/
│   ├── __init__.py
│   ├── main.py         # CLI entry point
│   ├── parser.py       # RFC 3164 / RFC 5424 syslog parser
│   ├── analyzer.py     # Aggregation and alert logic
│   ├── reader.py       # File / stdin / UDP log readers
│   └── reporter.py     # Console, JSON, and HTML output
├── config/
│   └── config.yaml     # Default configuration
├── logs/               # Mount your syslog files here
├── tests/
│   └── test_parser.py
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── requirements.txt
└── README.md
```

---

## Quick Start

### 1. Build the image

```bash
docker build -t log-analyzer:latest .
```

### 2. Analyze a log file

```bash
# Copy your syslog into ./logs/
cp /var/log/syslog ./logs/syslog.log

docker compose --profile file up
```

Reports are written to `./reports/report.json` and `./reports/report.html`.

### 3. Pipe from stdin

```bash
docker compose --profile stdin run --rm log-analyzer-stdin < /var/log/syslog
```

### 4. Live UDP syslog listener

```bash
docker compose --profile listen up -d

# Point your syslog daemon at localhost:514 (UDP)
# Example rsyslog rule: *.* @127.0.0.1:514
```

### 5. Run directly (no Compose)

```bash
# Single file
docker run --rm \
  -v /var/log/syslog:/logs/syslog.log:ro \
  -v $(pwd)/reports:/reports \
  log-analyzer:latest --file /logs/syslog.log

# Directory of log files
docker run --rm \
  -v /var/log:/logs:ro \
  -v $(pwd)/reports:/reports \
  log-analyzer:latest --dir /logs --pattern "*.log"

# Pipe via stdin
cat /var/log/syslog | docker run --rm -i \
  -v $(pwd)/reports:/reports \
  log-analyzer:latest --stdin
```

---

## Docker Compose Profiles

Three profiles are defined in `docker-compose.yml`. Pick the one that matches your use case.

| Profile | Service | Use case |
|---|---|---|
| `file` | `log-analyzer-file` | Analyze log files mounted at `./logs/` |
| `stdin` | `log-analyzer-stdin` | Pipe a log file into the container |
| `listen` | `log-analyzer-listen` | Receive live syslog over UDP on port 514 |

```bash
# file mode
docker compose --profile file up

# stdin mode
docker compose --profile stdin run --rm log-analyzer-stdin < /var/log/syslog

# listen mode (runs in background)
docker compose --profile listen up -d
```

---

## Dockerfile Overview

The image uses a **two-stage build** to keep the final image small and secure:

| Stage | Base image | Purpose |
|---|---|---|
| `builder` | `python:3.12-slim` | Install Python dependencies |
| `runtime` | `python:3.12-slim` | Run the application as a non-root user |

Key design decisions:
- Non-root user (`appuser`, UID 1001) — no root inside the container
- `/reports` and `/logs` are created as mount points
- Config is baked in at `/config/config.yaml` and can be overridden via a volume mount
- UDP port `514` is exposed for live syslog ingestion
- Health-check verifies the parser module loads correctly on every interval

---

## Configuration

Edit `config/config.yaml` or mount your own at `/config/config.yaml`:

```yaml
output_dir: /reports
output_formats: [json, html]

alert_rules:
  max_errors: 100             # exit code 2 if exceeded
  max_warnings: 500
  max_unparseable_pct: 10     # % of lines that can't be parsed
  host_burst_threshold: 1000  # alert if one host sends this many entries

server:
  host: "0.0.0.0"
  port: 514

logging:
  level: INFO   # DEBUG | INFO | WARNING | ERROR
```

Override at runtime:

```bash
docker run --rm \
  -v $(pwd)/my-config.yaml:/config/config.yaml:ro \
  -v $(pwd)/reports:/reports \
  -v /var/log/syslog:/logs/syslog.log:ro \
  log-analyzer:latest --file /logs/syslog.log
```

---

## CLI Reference

```
usage: python -m src.main [--file FILE | --stdin | --dir DIR | --listen]
                          [--pattern PATTERN] [--port PORT] [--config CONFIG]

Input (pick one):
  -f, --file FILE       Path to a syslog file (.log or .gz)
  -s, --stdin           Read from stdin
  -d, --dir DIR         Directory of log files
  -l, --listen          Start a live UDP syslog listener

Options:
  -p, --pattern PATTERN Glob pattern for --dir (default: *.log)
      --port PORT       UDP port for --listen (default: 514)
  -c, --config CONFIG   Path to YAML config (default: /config/config.yaml)
  -h, --help            Show this help message and exit
```

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | Success, no alerts triggered |
| `1` | Fatal error (no input found, bad config) |
| `2` | Analysis complete but ≥1 alert threshold exceeded |

---

## Sample Console Output

```
============================================================
  SYSLOG ANALYSIS REPORT
============================================================
  Total entries    : 24,318
  Errors           : 142
  Warnings         : 503
  Unparseable      : 17

  ⚠  ALERTS
    • HIGH ERROR RATE: 142 error-level entries (threshold: 100)

  Severity Breakdown:
    INFO         18,412  ████████████████████████████████████████
    WARNING         503  █
    ERROR           142
    CRITICAL         38

  Top 10 Processes:
    sshd                           5,210
    kernel                         4,891
    systemd                        3,302
    ...

  Top 10 Hostnames:
    web-server-01                 12,441
    db-server-02                   8,320
    ...
============================================================
```

---

## Running Tests

```bash
# Install dependencies
pip install PyYAML pytest

# Run tests
python -m pytest tests/ -v
```

---

## Local Development (without Docker)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Analyze a file
python -m src.main --file /var/log/syslog --config config/config.yaml

# Stdin
cat /var/log/syslog | python -m src.main --stdin --config config/config.yaml
```

---

## Requirements

- Docker 20.10+ (for Compose v2 `--profile` support)
- Python 3.9+ (for local development)
- PyYAML 6.0.2

---

## License

MIT

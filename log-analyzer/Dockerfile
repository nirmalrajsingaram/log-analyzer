# ============================================================
# Stage 1 — Build / dependency installation
# ============================================================
FROM python:3.12-slim AS builder

WORKDIR /build

# Install dependencies into an isolated prefix so we can copy
# only what we need into the final image.
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ============================================================
# Stage 2 — Runtime image
# ============================================================
FROM python:3.12-slim AS runtime

LABEL maintainer="log-analyzer"
LABEL description="Syslog Log Analyzer — parses RFC 3164 / RFC 5424 syslog and produces JSON + HTML reports"

# Copy installed packages from the builder stage
COPY --from=builder /install /usr/local

# Create non-root user for security
RUN groupadd --gid 1001 appgroup && \
    useradd  --uid 1001 --gid appgroup --no-create-home --shell /sbin/nologin appuser

WORKDIR /app

# Copy application source
COPY src/ ./src/

# Create directories with correct ownership
RUN mkdir -p /reports /logs /config && \
    chown -R appuser:appgroup /app /reports /logs /config

# Default config is baked in; users can mount their own at /config/config.yaml
COPY config/config.yaml /config/config.yaml

# Drop to non-root
USER appuser

# Expose UDP syslog port (only used in --listen mode)
EXPOSE 514/udp

# Health-check: verify Python and the package import correctly
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from src.parser import parse_line; print('ok')" || exit 1

# Default: analyze /var/log/syslog if mounted; override via CMD or entrypoint
ENTRYPOINT ["python", "-m", "src.main"]
CMD ["--help"]

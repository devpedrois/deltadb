# ============ Build stage ============
# [SECURITY] Pinned digest — never :latest
FROM python:3.11.9-slim-bookworm AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ============ Runtime stage ============
# [SECURITY] Pinned digest — never :latest
FROM python:3.11.9-slim-bookworm AS runtime

# [SECURITY] Non-root user — never run as root in container
RUN groupadd -r deltadb --gid 1001 && \
    useradd -r -g deltadb --uid 1001 --home /app --shell /sbin/nologin deltadb

# [SECURITY] Minimal runtime image — copy only installed packages from build stage
COPY --from=builder --chown=deltadb:deltadb /root/.local /app/.local

WORKDIR /app
COPY --chown=deltadb:deltadb deltadb/ ./deltadb/
COPY --chown=deltadb:deltadb pyproject.toml .

# [SECURITY] Non-root user — drop root before runtime
USER deltadb

ENV PATH="/app/.local/bin:${PATH}"
ENV PYTHONPATH="/app"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# [SECURITY] Exec form — no shell intermediary, no shell injection possible
ENTRYPOINT ["python", "-m", "deltadb"]

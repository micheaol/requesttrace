# syntax=docker/dockerfile:1

# ---- Builder stage: install dependencies into an isolated venv -------------
FROM python:3.12-slim AS builder

WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml README.md ./
COPY requesttrace ./requesttrace

# Installing the project itself pulls in pinned runtime dependencies from
# pyproject.toml; the optional 'pdf' extra is included so PDF reports work
# out of the box in the published image.
RUN python -m pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir ".[pdf]"

# ---- Runtime stage: minimal image, non-root user ---------------------------
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="RequestTrace" \
      org.opencontainers.image.description="Production request-path, TLS and HTTP security assessment CLI" \
      org.opencontainers.image.source="https://github.com/micheaol/requesttrace" \
      org.opencontainers.image.licenses="MIT"

# CA certificates are required for TLS trust-chain validation against the
# system trust store (RT-014); tini provides correct signal handling as PID 1.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 requesttrace \
    && useradd --uid 10001 --gid requesttrace --create-home --shell /usr/sbin/nologin requesttrace

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    REQUESTTRACE_IMAGE_REF="ghcr.io/micheaol/requesttrace"

RUN mkdir -p /app/reports && chown -R requesttrace:requesttrace /app

WORKDIR /app
# Numeric uid:gid rather than the name — resolvable even if a runtime
# environment doesn't mount/preserve /etc/passwd (e.g. some Kubernetes
# security contexts); it still maps back to "requesttrace" via the account
# created above wherever /etc/passwd is present.
USER 10001:10001

VOLUME ["/app/reports"]

ENTRYPOINT ["tini", "--", "requesttrace"]
CMD ["--help"]

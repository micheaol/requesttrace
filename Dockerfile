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
#
# pip is uninstalled from the venv in this same step, before it's ever
# copied into the runtime stage — not after. A scanner analyzing the final
# runtime image sees each stage's COPY as one flat snapshot, but the
# runtime stage's *own* layer history still matters: if pip were copied in
# and only removed by a later RUN there, that stage would carry an
# add-then-delete history for it that some layer-diff scanners (Trivy
# included) don't fully reconcile for language-package files, resurfacing
# pip's vendored deps (e.g. msgpack) as false positives even though they
# are provably absent from the image that actually runs. Removing it here
# means the runtime stage's layer history never contains pip at all.
RUN python -m pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir ".[pdf]" \
    && pip uninstall -y pip

# ---- Runtime stage: minimal image, non-root user ---------------------------
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="RequestTrace" \
      org.opencontainers.image.description="Production request-path, TLS and HTTP security assessment CLI" \
      org.opencontainers.image.source="https://github.com/micheaol/requesttrace" \
      org.opencontainers.image.licenses="MIT"

# CA certificates are required for TLS trust-chain validation against the
# system trust store (RT-014); tini provides correct signal handling as PID 1.
# `apt-get upgrade` picks up any OS-package security patch Debian has
# already shipped for this base image (e.g. an openssl point release)
# instead of only whatever was baked in when the base image was published.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    # The base image ships its own system-wide pip (plus an unused
    # ensurepip bundle) that we never invoke — the app runs from
    # /opt/venv exclusively. Both vendor their own old dependencies
    # (e.g. pip's vendored pkg_resources/msgpack), which only adds
    # unfixable scanner noise for code that never executes here.
    && rm -rf /usr/local/lib/python3.12/ensurepip \
    && rm -rf /usr/local/lib/python3.12/site-packages/pip* \
    && rm -f /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.12

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

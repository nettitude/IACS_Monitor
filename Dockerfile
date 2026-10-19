# Needs BuildKit (default since Docker 23): RUN --mount secrets, COPY --chmod.
#
# IACS_Monitor container image (SQLite on a /data volume by default).
#
# Targets
#   runtime (default) - the application: API + web UI (/ui) + scheduled
#                       reviews + PDF reports, one uvicorn process.
#   dev               - runtime + the test suite and its tools (pytest, ...);
#                       used by docker-compose.dev.yml and to run the suite
#                       inside the exact image that ships.
#
# Dependencies are installed ONLY from requirements-lock.txt (exact versions,
# --no-deps): the set the test suite, the tabletops and the real-config run
# were verified with.  See docs/docker-install.md.
#
# Build:  ./build.sh                    (or: docker build -t iasc-monitor .)
# Run:    docker compose up -d          (named volume iasc_data -> /data)

# Python 3.11 - the interpreter line the suite was verified on (3.11.15).
# Wheels are cp311, so any 3.11.x patch release works.  For an immutable
# build pin the digest:  --build-arg PYTHON_BASE=python@sha256:<digest>
ARG PYTHON_VERSION=3.11
ARG PYTHON_BASE=python:${PYTHON_VERSION}-slim-bookworm

# ------------------------------------------------------------- builder --
FROM ${PYTHON_BASE} AS builder

# Every locked package ships a manylinux wheel for amd64 and arm64, so no
# compiler is needed.  On another architecture build with
#   --build-arg BUILD_TOOLS=true
ARG BUILD_TOOLS=false
RUN if [ "$BUILD_TOOLS" = "true" ]; then \
        apt-get update && apt-get install -y --no-install-recommends build-essential libpq-dev \
        && rm -rf /var/lib/apt/lists/*; \
    fi

WORKDIR /build
COPY requirements-lock.txt requirements-dev-lock.txt ./

# Behind a TLS-inspecting proxy, pass its CA as a build secret:
#   docker build --secret id=pip_ca,src=/path/to/ca.pem ...
# (and --build-arg HTTPS_PROXY=... if pip needs a proxy).
RUN --mount=type=secret,id=pip_ca,required=false \
    if [ -s /run/secrets/pip_ca ]; then export PIP_CERT=/run/secrets/pip_ca; fi; \
    python -m pip install --no-cache-dir --user --ignore-installed --no-deps \
        --no-warn-script-location -r requirements-lock.txt

# Test tools for the dev target, installed separately so the runtime image
# never contains them.
RUN --mount=type=secret,id=pip_ca,required=false \
    if [ -s /run/secrets/pip_ca ]; then export PIP_CERT=/run/secrets/pip_ca; fi; \
    python -m pip install --no-cache-dir --ignore-installed --no-deps \
        --no-warn-script-location --target /build/devdeps -r requirements-dev-lock.txt

# ------------------------------------------------------------- runtime --
FROM ${PYTHON_BASE} AS runtime

# Offline pcap reading only (scapy parses pcap/pcapng in pure Python): no
# libpcap at runtime.  Non-root user.
RUN groupadd --gid 1000 iasc && useradd --uid 1000 --gid iasc --create-home iasc

WORKDIR /app

COPY --from=builder --chown=iasc:iasc /root/.local /home/iasc/.local

COPY --chown=iasc:iasc app/ ./app/
COPY --chown=iasc:iasc ui/ ./ui/
COPY --chown=iasc:iasc sample_data/ ./sample_data/
COPY --chown=iasc:iasc alembic/ ./alembic/
COPY --chown=iasc:iasc alembic.ini generate_report.py backup_db.py requirements-lock.txt ./
COPY --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# /data holds the SQLite database (+ WAL), the scheduler lock, upload spool
# files (TMPDIR) and backups.  Declared a VOLUME so even a plain `docker run`
# without -v keeps it outside the container layer.
RUN mkdir -p /data && chown iasc:iasc /data
VOLUME ["/data"]

ENV PATH=/home/iasc/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    IACS_DATABASE_URL=sqlite:////data/iasc_monitor.db \
    TMPDIR=/data/tmp

USER iasc
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=3)" || exit 1

# The entrypoint prepares /data, applies pending migrations (`alembic upgrade
# head`; a no-op at head) and then execs CMD.
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
# One worker: the scheduler guard is a per-host file lock and SQLite has one
# writer - more workers add contention, not throughput.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]

# ----------------------------------------------------------------- dev --
FROM runtime AS dev

COPY --from=builder --chown=iasc:iasc /build/devdeps /home/iasc/devdeps
ENV PYTHONPATH=/home/iasc/devdeps \
    PATH=/home/iasc/devdeps/bin:/home/iasc/.local/bin:$PATH
COPY --chown=iasc:iasc tests/ ./tests/
COPY --chown=iasc:iasc docs/ ./docs/
COPY --chown=iasc:iasc requirements.txt requirements-dev.txt requirements-dev-lock.txt README.md ./

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload", "--reload-dir", "app"]

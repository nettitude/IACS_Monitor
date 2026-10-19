#!/usr/bin/env bash
# IACS_Monitor — bare-metal / VM installer
# Tested on: Ubuntu 22.04+, Debian 12, RHEL/Rocky 9, Fedora 39+
#
# Usage:
#   sudo bash install.sh               # interactive, installs to /opt/iasc_monitor
#   sudo bash install.sh --prefix /srv/iasc_monitor --port 8888
#   sudo bash install.sh --no-service  # skip systemd unit creation
#   sudo bash install.sh --help

set -euo pipefail
IFS=$'\n\t'

# ─── defaults ─────────────────────────────────────────────────────────────────
INSTALL_PREFIX="/opt/iasc_monitor"
BIND_HOST="127.0.0.1"
BIND_PORT="8000"
SERVICE_USER="iasc"
SERVICE_NAME="iasc_monitor"
CREATE_SERVICE=true
MIN_PYTHON_MINOR=11      # Python 3.11+

# ─── colour helpers ───────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ─── argument parsing ─────────────────────────────────────────────────────────
usage() {
    cat <<EOF
Usage: sudo bash install.sh [OPTIONS]

Options:
  --prefix PATH      Install root directory  (default: ${INSTALL_PREFIX})
  --host  HOST       Bind host               (default: ${BIND_HOST})
  --port  PORT       Bind port               (default: ${BIND_PORT})
  --user  USER       System service account  (default: ${SERVICE_USER})
  --no-service       Skip systemd unit creation
  --help             Show this help

Environment variables (override defaults):
  IACS_DATABASE_URL   SQLAlchemy DB URL  (default: sqlite:///./iasc_monitor.db)
  IACS_ALLOWED_ORIGINS  Comma-separated CORS origins
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)     INSTALL_PREFIX="$2"; shift 2 ;;
        --host)       BIND_HOST="$2";      shift 2 ;;
        --port)       BIND_PORT="$2";      shift 2 ;;
        --user)       SERVICE_USER="$2";   shift 2 ;;
        --no-service) CREATE_SERVICE=false; shift ;;
        --help|-h)    usage ;;
        *) die "Unknown option: $1  (try --help)" ;;
    esac
done

# ─── root check ───────────────────────────────────────────────────────────────
[[ "$(id -u)" -eq 0 ]] || die "Run as root (sudo bash install.sh)"

# ─── detect OS and package manager ───────────────────────────────────────────
info "Detecting operating system …"
if command -v apt-get &>/dev/null; then
    PKG_MANAGER="apt"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
else
    die "Unsupported OS — install Python 3.11+, libpcap, and then re-run with --no-service if needed."
fi
info "Package manager: ${PKG_MANAGER}"

# ─── system packages ─────────────────────────────────────────────────────────
info "Installing system dependencies …"
if [[ "${PKG_MANAGER}" == "apt" ]]; then
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        libpcap-dev libpcap0.8 \
        curl ca-certificates
elif [[ "${PKG_MANAGER}" == "dnf" ]] || [[ "${PKG_MANAGER}" == "yum" ]]; then
    "${PKG_MANAGER}" install -y \
        python3 python3-pip \
        libpcap libpcap-devel \
        curl ca-certificates
fi
success "System packages installed."

# ─── Python version check ─────────────────────────────────────────────────────
info "Checking Python version …"
PYTHON_BIN=""
for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "${candidate}" &>/dev/null; then
        minor=$("${candidate}" -c "import sys; print(sys.version_info.minor)")
        major=$("${candidate}" -c "import sys; print(sys.version_info.major)")
        if [[ "${major}" -eq 3 && "${minor}" -ge "${MIN_PYTHON_MINOR}" ]]; then
            PYTHON_BIN="${candidate}"
            break
        fi
    fi
done
[[ -n "${PYTHON_BIN}" ]] || die "Python 3.${MIN_PYTHON_MINOR}+ not found. Install it and re-run."
PYTHON_VERSION=$("${PYTHON_BIN}" --version)
success "Found: ${PYTHON_VERSION} (${PYTHON_BIN})"

# ─── source directory ────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
info "Source directory: ${SCRIPT_DIR}"
for f in requirements.txt app/main.py; do
    [[ -f "${SCRIPT_DIR}/${f}" ]] || die "Missing ${f} — run install.sh from the iasc_monitor directory."
done

# ─── install prefix ──────────────────────────────────────────────────────────
info "Installing to ${INSTALL_PREFIX} …"
mkdir -p "${INSTALL_PREFIX}"

# Copy source tree (rsync preferred, tar fallback).
#
# The same exclude list is used on both paths. Nothing is ever deleted from
# ${INSTALL_PREFIX}: on a re-install / upgrade the production database, .env
# and venv there must survive. (T1-01: the old cp fallback copied everything
# and then ran `rm -f ${INSTALL_PREFIX}/iasc_monitor.db`, which deleted the
# PRODUCTION database whenever rsync was not installed.)
COPY_EXCLUDES=(
    '.git' '__pycache__' '*.pyc' '.pytest_cache'
    '.venv' '.env' 'dist'
    'iasc_monitor.db' '*.db' '*.db-journal' '*.db-wal' '*.db-shm'
)
SRC_REAL="$(cd "${SCRIPT_DIR}" && pwd -P)"
DST_REAL="$(cd "${INSTALL_PREFIX}" && pwd -P)"
if [[ "${SRC_REAL}" == "${DST_REAL}" ]]; then
    info "Source directory is the install prefix — nothing to copy."
elif command -v rsync &>/dev/null; then
    RSYNC_ARGS=()
    for pat in "${COPY_EXCLUDES[@]}"; do RSYNC_ARGS+=("--exclude=${pat}"); done
    rsync -a "${RSYNC_ARGS[@]}" "${SCRIPT_DIR}/" "${INSTALL_PREFIX}/"
else
    # tar honours the exclude list, so dev artefacts are never copied and
    # nothing needs removing from the destination afterwards.
    TAR_ARGS=()
    for pat in "${COPY_EXCLUDES[@]}"; do TAR_ARGS+=("--exclude=${pat}"); done
    tar -C "${SCRIPT_DIR}" "${TAR_ARGS[@]}" -cf - . | tar -C "${INSTALL_PREFIX}" -xf -
fi
success "Source files copied."

# ─── virtual environment ──────────────────────────────────────────────────────
VENV_DIR="${INSTALL_PREFIX}/.venv"
info "Creating virtual environment at ${VENV_DIR} …"
"${PYTHON_BIN}" -m venv "${VENV_DIR}"
VENV_PIP="${VENV_DIR}/bin/pip"
VENV_PYTHON="${VENV_DIR}/bin/python"
"${VENV_PIP}" install --quiet --upgrade pip setuptools wheel
success "Virtual environment created."

info "Installing Python dependencies …"
# The locked set (exact versions the suite was verified with) when present.
if [ -f "${INSTALL_PREFIX}/requirements-lock.txt" ]; then
    "${VENV_PIP}" install --quiet --no-deps -r "${INSTALL_PREFIX}/requirements-lock.txt"
else
    "${VENV_PIP}" install --quiet -r "${INSTALL_PREFIX}/requirements.txt"
fi
success "Dependencies installed."

# ─── data directory (A-27) ───────────────────────────────────────────────────
# Code and venv stay root-owned and read-only to the service account; only
# this directory (SQLite DB + journal/WAL, scheduler lock) is writable by it.
DATA_DIR="${INSTALL_PREFIX}/data"
mkdir -p "${DATA_DIR}"
LEGACY_DB="${INSTALL_PREFIX}/iasc_monitor.db"
if [[ -f "${LEGACY_DB}" && ! -e "${DATA_DIR}/iasc_monitor.db" ]]; then
    info "Moving legacy database ${LEGACY_DB} → ${DATA_DIR}/"
    for ext in "" "-journal" "-wal" "-shm"; do
        [[ -e "${LEGACY_DB}${ext}" ]] && mv "${LEGACY_DB}${ext}" "${DATA_DIR}/"
    done
    if [[ -f "${INSTALL_PREFIX}/.env" ]]; then
        sed -i "s#^IACS_DATABASE_URL=sqlite:///${LEGACY_DB}\$#IACS_DATABASE_URL=sqlite:///${DATA_DIR}/iasc_monitor.db#" "${INSTALL_PREFIX}/.env"
    fi
fi
rm -f "${INSTALL_PREFIX}/iasc_scheduler.lock"

# ─── .env template ───────────────────────────────────────────────────────────
ENV_FILE="${INSTALL_PREFIX}/.env"
if [[ ! -f "${ENV_FILE}" ]]; then
    info "Writing .env template → ${ENV_FILE}"
    cat > "${ENV_FILE}" <<EOF
# IACS_Monitor runtime environment
# Edit this file, then restart the service: systemctl restart ${SERVICE_NAME}

# Database (SQLite default; replace with postgresql+psycopg2:// for Postgres)
IACS_DATABASE_URL=sqlite:///${DATA_DIR}/iasc_monitor.db

# Scheduler single-instance lock (must be in a service-writable directory)
IACS_SCHEDULER_LOCK=${DATA_DIR}/iasc_scheduler.lock

# CORS origins for the web UI (comma-separated)
# Example: IACS_ALLOWED_ORIGINS=http://10.0.0.10:8000,https://iasc.example.com
IACS_ALLOWED_ORIGINS=

# Uvicorn bind
IACS_HOST=${BIND_HOST}
IACS_PORT=${BIND_PORT}
EOF
    chmod 640 "${ENV_FILE}"
else
    warn ".env already exists — skipping template write."
fi

# ─── alembic DB migration ────────────────────────────────────────────────────
info "Running database migrations …"
(
    cd "${INSTALL_PREFIX}"
    # source .env so alembic env.py sees IACS_DATABASE_URL
    set -a; [[ -f .env ]] && . .env; set +a

    # A database created by the app itself (init_db / create_all) before
    # migrations were tracked has tables but no alembic_version row, and
    # `alembic upgrade head` would fail with "table ... already exists".
    # Detect that, stamp it at the baseline, and let the idempotent
    # migrations + reconcile revision bring it to head.
    state="$("${VENV_PYTHON}" - <<'PY'
import os
from sqlalchemy import create_engine, inspect
url = os.environ.get("IACS_DATABASE_URL", "sqlite:///./iasc_monitor.db")
try:
    insp = inspect(create_engine(url))
    tables = insp.get_table_names()
except Exception:
    tables = []
print("unstamped" if tables and "alembic_version" not in tables else "ok")
PY
)"
    if [[ "${state}" == "unstamped" ]]; then
        # Every revision after the baseline is idempotent and d4e5f6a7b8c9
        # adds whatever columns/indexes an older create_all schema lacks, so
        # stamping at the baseline and upgrading is safe for any legacy DB.
        echo "Existing database has no Alembic stamp; stamping at baseline 0001baseline0 and reconciling." >&2
        "${VENV_DIR}/bin/alembic" stamp 0001baseline0
    fi
    "${VENV_DIR}/bin/alembic" upgrade head
) || die "Database migration failed. Fix the error above before starting the service.
  Manual retry: cd ${INSTALL_PREFIX} && set -a && . ./.env && set +a && .venv/bin/alembic upgrade head"
success "Database migrations applied."

# ─── service account ─────────────────────────────────────────────────────────
if ${CREATE_SERVICE}; then
    if ! id -u "${SERVICE_USER}" &>/dev/null; then
        info "Creating system user '${SERVICE_USER}' …"
        useradd --system --no-create-home \
                --shell /usr/sbin/nologin \
                --comment "IACS_Monitor service account" \
                "${SERVICE_USER}"
        success "User '${SERVICE_USER}' created."
    else
        info "User '${SERVICE_USER}' already exists."
    fi
    # A-27: code + venv root-owned, world-readable but not writable by the
    # service; only DATA_DIR belongs to the service account.
    chown -R root:root "${INSTALL_PREFIX}"
    chmod -R go-w "${INSTALL_PREFIX}"
    chown -R "${SERVICE_USER}:${SERVICE_USER}" "${DATA_DIR}"
    chmod 750 "${DATA_DIR}"
    if [[ -f "${ENV_FILE}" ]]; then
        chown "root:${SERVICE_USER}" "${ENV_FILE}"
        chmod 640 "${ENV_FILE}"
    fi
    if grep -q '^IACS_DATABASE_URL=sqlite:///' "${ENV_FILE}" 2>/dev/null \
       && ! grep -q "^IACS_DATABASE_URL=sqlite:///${DATA_DIR}/" "${ENV_FILE}"; then
        warn "IACS_DATABASE_URL in ${ENV_FILE} points outside ${DATA_DIR}; the service account cannot write there."
    fi
fi

# ─── systemd unit ────────────────────────────────────────────────────────────
if ${CREATE_SERVICE}; then
    if ! command -v systemctl &>/dev/null; then
        warn "systemctl not found — skipping service installation."
        CREATE_SERVICE=false
    fi
fi

if ${CREATE_SERVICE}; then
    UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
    info "Writing systemd unit → ${UNIT_FILE}"
    cat > "${UNIT_FILE}" <<EOF
[Unit]
Description=IACS_Monitor — ICS/OT Network Monitor
Documentation=https://github.com/your-org/iasc_monitor
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${INSTALL_PREFIX}

# Defaults; the .env loaded below overrides them (EnvironmentFile= settings
# take precedence over Environment=), so editing IACS_HOST / IACS_PORT in
# .env and restarting the service changes the bind address (T3-43).
Environment=IACS_HOST=${BIND_HOST}
Environment=IACS_PORT=${BIND_PORT}
Environment=IACS_SCHEDULER_LOCK=${DATA_DIR}/iasc_scheduler.lock
# Load .env for IACS_DATABASE_URL and other env vars
EnvironmentFile=-${INSTALL_PREFIX}/.env

# Apply any pending migrations before every start (no-op when at head).
ExecStartPre=${VENV_DIR}/bin/alembic -c ${INSTALL_PREFIX}/alembic.ini upgrade head
ExecStart=${VENV_DIR}/bin/uvicorn app.main:app \
    --host \${IACS_HOST} \
    --port \${IACS_PORT} \
    --workers 1

Restart=on-failure
RestartSec=5s
TimeoutStartSec=30
TimeoutStopSec=15

# Security hardening
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${DATA_DIR}
NoNewPrivileges=true
# Code is read-only; Python must not try to write __pycache__ there.
Environment=PYTHONDONTWRITEBYTECODE=1
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "${UNIT_FILE}"
    systemctl daemon-reload
    systemctl enable --now "${SERVICE_NAME}" \
        && success "Service '${SERVICE_NAME}' enabled and started." \
        || warn "Could not start service — check: journalctl -u ${SERVICE_NAME}"
fi

# ─── done ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════╗"
echo -e "║         IACS_Monitor installation complete           ║"
echo -e "╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Install prefix : ${CYAN}${INSTALL_PREFIX}${NC}"
echo -e "  API endpoint   : ${CYAN}http://${BIND_HOST}:${BIND_PORT}${NC}"
echo -e "  Config         : ${CYAN}${ENV_FILE}${NC}"
if ${CREATE_SERVICE}; then
echo ""
echo -e "  Service control:"
echo -e "    ${BOLD}systemctl status  ${SERVICE_NAME}${NC}"
echo -e "    ${BOLD}systemctl restart ${SERVICE_NAME}${NC}"
echo -e "    ${BOLD}journalctl -u ${SERVICE_NAME} -f${NC}"
else
echo ""
echo -e "  Manual start:"
echo -e "    ${BOLD}cd ${INSTALL_PREFIX} && .venv/bin/uvicorn app.main:app --host ${BIND_HOST} --port ${BIND_PORT}${NC}"
fi
echo ""

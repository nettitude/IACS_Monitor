#!/usr/bin/env bash
# IACS_Monitor — build a versioned source-distribution tarball
#
# Usage:
#   bash make-dist.sh              # auto-detects version from git tag or VERSION file
#   bash make-dist.sh 1.2.3        # explicit version
#   bash make-dist.sh --out /tmp   # write tarball to /tmp/
#   bash make-dist.sh --help

set -euo pipefail
IFS=$'\n\t'

# ─── defaults ─────────────────────────────────────────────────────────────────
OUT_DIR="$(pwd)/dist"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── colour helpers ───────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

usage() {
    cat <<EOF
Usage: bash make-dist.sh [VERSION] [OPTIONS]

  VERSION           Version string (e.g. 1.2.3).  Auto-detected if omitted.
                    Detection order: explicit arg → git tag → VERSION file → "dev"

Options:
  --out PATH        Output directory for the tarball  (default: ./dist)
  --help            Show this help

Output:
  dist/iasc_monitor-<VERSION>.tar.gz
    └── iasc_monitor-<VERSION>/
          ├── app/
          ├── ui/
          ├── alembic/
          ├── alembic.ini
          ├── requirements.txt
          ├── install.sh
          ├── make-dist.sh
          └── README.md

The tarball does NOT include:
  .git/  __pycache__/  *.pyc  .venv/  iasc_monitor.db  tests/
  dist/  Dockerfile  docker-compose.yml  build.sh  .env  .env.*
EOF
    exit 0
}

# ─── argument parsing ─────────────────────────────────────────────────────────
VERSION_ARG=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --out)  OUT_DIR="$2"; shift 2 ;;
        --help|-h) usage ;;
        --*)    die "Unknown option: $1  (try --help)" ;;
        *)      VERSION_ARG="$1"; shift ;;
    esac
done

# ─── determine version ───────────────────────────────────────────────────────
if [[ -n "${VERSION_ARG}" ]]; then
    VERSION="${VERSION_ARG}"
elif git -C "${SCRIPT_DIR}" describe --tags --exact-match 2>/dev/null | grep -qE '^v?[0-9]'; then
    VERSION="$(git -C "${SCRIPT_DIR}" describe --tags --exact-match 2>/dev/null | sed 's/^v//')"
elif git -C "${SCRIPT_DIR}" describe --tags 2>/dev/null | grep -qE '^v?[0-9]'; then
    VERSION="$(git -C "${SCRIPT_DIR}" describe --tags 2>/dev/null | sed 's/^v//')"
elif [[ -f "${SCRIPT_DIR}/VERSION" ]]; then
    VERSION="$(tr -d '[:space:]' < "${SCRIPT_DIR}/VERSION")"
else
    VERSION="dev"
    warn "Could not detect version — using '${VERSION}'.  Pass a version string or tag the repo."
fi
info "Version: ${VERSION}"

# ─── validate we're in the right directory ────────────────────────────────────
for f in requirements.txt app/main.py install.sh; do
    [[ -f "${SCRIPT_DIR}/${f}" ]] || die "Missing ${f} — run make-dist.sh from the iasc_monitor root."
done

# ─── scratch directory ───────────────────────────────────────────────────────
PACKAGE_NAME="iasc_monitor-${VERSION}"
STAGING_DIR="$(mktemp -d)"
trap 'rm -rf "${STAGING_DIR}"' EXIT
STAGE="${STAGING_DIR}/${PACKAGE_NAME}"
mkdir -p "${STAGE}"

info "Staging to ${STAGING_DIR} …"

# ─── files to include ────────────────────────────────────────────────────────
# Explicit allowlist keeps the tarball clean regardless of what lives in the repo
INCLUDE_DIRS=(app ui alembic docs sample_data)
INCLUDE_FILES=(requirements.txt requirements-dev.txt requirements-lock.txt requirements-dev-lock.txt alembic.ini install.sh make-dist.sh generate_report.py backup_db.py)
# Include README if present
[[ -f "${SCRIPT_DIR}/README.md" ]] && INCLUDE_FILES+=(README.md)
[[ -f "${SCRIPT_DIR}/VERSION"   ]] && INCLUDE_FILES+=(VERSION)

for d in "${INCLUDE_DIRS[@]}"; do
    if [[ -d "${SCRIPT_DIR}/${d}" ]]; then
        cp -r "${SCRIPT_DIR}/${d}" "${STAGE}/${d}"
    else
        warn "Directory not found, skipping: ${d}"
    fi
done

for f in "${INCLUDE_FILES[@]}"; do
    if [[ -f "${SCRIPT_DIR}/${f}" ]]; then
        cp "${SCRIPT_DIR}/${f}" "${STAGE}/${f}"
    else
        warn "File not found, skipping: ${f}"
    fi
done

# ─── stamp version into install.sh ───────────────────────────────────────────
if grep -q 'IACS_MONITOR_VERSION' "${STAGE}/install.sh" 2>/dev/null; then
    sed -i "s/IACS_MONITOR_VERSION=.*/IACS_MONITOR_VERSION=\"${VERSION}\"/" "${STAGE}/install.sh"
fi

# ─── purge generated / dev artefacts from staging ────────────────────────────
find "${STAGE}" -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
find "${STAGE}" -name '*.pyc' -delete 2>/dev/null || true
find "${STAGE}" -name '*.pyo' -delete 2>/dev/null || true
find "${STAGE}" -name '.DS_Store' -delete 2>/dev/null || true
find "${STAGE}" -name '*.db'  -delete 2>/dev/null || true   # no stale SQLite
find "${STAGE}" -name '.env*' -delete 2>/dev/null || true   # no secrets

# ensure install.sh is executable inside the tarball
chmod +x "${STAGE}/install.sh" "${STAGE}/make-dist.sh" 2>/dev/null || true

# ─── create tarball ──────────────────────────────────────────────────────────
mkdir -p "${OUT_DIR}"
TARBALL="${OUT_DIR}/${PACKAGE_NAME}.tar.gz"

info "Building tarball …"
tar -C "${STAGING_DIR}" -czf "${TARBALL}" "${PACKAGE_NAME}"

TARBALL_SIZE="$(du -sh "${TARBALL}" | cut -f1)"
success "Tarball built: ${TARBALL} (${TARBALL_SIZE})"

# ─── verify tarball ──────────────────────────────────────────────────────────
info "Verifying tarball integrity …"
_contents="$(tar -tzf "${TARBALL}")"
echo "${_contents}" | grep -qF "${PACKAGE_NAME}/install.sh" \
    || die "Verification failed: install.sh not found inside tarball."
echo "${_contents}" | grep -qF "requirements.txt" \
    || die "Verification failed: requirements.txt not found inside tarball."
echo "${_contents}" | grep -qF "${PACKAGE_NAME}/app/" \
    || die "Verification failed: app/ directory not found inside tarball."
success "Tarball verified."

# ─── generate sha256 checksum ────────────────────────────────────────────────
CHECKSUM_FILE="${TARBALL}.sha256"
# Record the bare file name (not the build machine's absolute path) so
# `sha256sum -c` works wherever the tarball and .sha256 are copied (T3-42).
_tar_dir="$(dirname "${TARBALL}")"
_tar_name="$(basename "${TARBALL}")"
if command -v sha256sum &>/dev/null; then
    (cd "${_tar_dir}" && sha256sum "${_tar_name}") > "${CHECKSUM_FILE}"
    success "Checksum: ${CHECKSUM_FILE}"
elif command -v shasum &>/dev/null; then
    (cd "${_tar_dir}" && shasum -a 256 "${_tar_name}") > "${CHECKSUM_FILE}"
    success "Checksum: ${CHECKSUM_FILE}"
else
    warn "sha256sum / shasum not found — skipping checksum."
fi

# ─── print contents summary ──────────────────────────────────────────────────
info "Tarball contents:"
tar -tzf "${TARBALL}" | sed 's/^/    /'

echo ""
echo -e "${BOLD}${GREEN}Distribution package ready!${NC}"
echo ""
echo -e "  Tarball  : ${CYAN}${TARBALL}${NC}"
[[ -f "${CHECKSUM_FILE}" ]] && \
echo -e "  SHA-256  : ${CYAN}${CHECKSUM_FILE}${NC}"
echo ""
echo -e "  Install on a target machine:"
echo -e "    ${BOLD}tar xzf ${PACKAGE_NAME}.tar.gz${NC}"
echo -e "    ${BOLD}cd ${PACKAGE_NAME}${NC}"
echo -e "    ${BOLD}sudo bash install.sh${NC}"
echo ""

"""
Multi-site test helpers (phases 1-3).

Every non-log upload route requires ``site`` (id, name or code).  Existing
tests are about other behaviour, so they upload to the Default site (code
``default``), which init_db / migration c0d1e2f3a4b5 create and app.sites
creates on demand in a fresh test database.
"""
DEFAULT_SITE = "default"

# Upload routes that require ``site`` (query parameter; /attestation takes a
# form field).  Log routes (/ingest/syslog, /ingest/forti-*) do not.
SITE_REQUIRED_ROUTES = (
    "/ingest/pcap", "/ingest/pcap-fw", "/ingest/arp", "/ingest/firewall",
    "/ingest/fortigate-config", "/ingest/switch", "/ingest/mac-table",
    "/ingest/baseline/comms-matrix", "/ingest/baseline/approved-hosts",
    "/ingest/baseline/asset-inventory", "/ingest/baseline/reviewed-policies",
)


# Log routes (multi-site phase 3): ``site`` is OPTIONAL there and means "map
# lines of unknown devices to this site".  The conftest auto-site adds
# site=default to them too, so tests written before per-line routing keep
# storing their log events in the Default site.
LOG_ROUTES = ("/ingest/syslog", "/ingest/forti-syslog", "/ingest/forti-event",
              "/ingest/forti-report")


def is_log_route(url: str) -> bool:
    path = url.split("?", 1)[0]
    return any(path.endswith(r) for r in LOG_ROUTES)


def needs_site(url: str) -> bool:
    path = url.split("?", 1)[0]
    return any(path.endswith(r) for r in SITE_REQUIRED_ROUTES)


def site_params(url: str, params=None, site=DEFAULT_SITE) -> dict:
    """``params`` plus ``site`` when ``url`` is a site-required upload route
    (an explicit ``site`` in ``params`` wins)."""
    out = dict(params or {})
    if needs_site(url) or is_log_route(url):
        out.setdefault("site", site)
    return out


def site_form(data=None, site=DEFAULT_SITE) -> dict:
    """Form fields for POST /attestation plus ``site``."""
    out = dict(data or {})
    out.setdefault("site", site)
    return out

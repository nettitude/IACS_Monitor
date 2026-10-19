"""
Session-wide test isolation.

app.db reads IACS_DATABASE_URL at import time and defaults to
./iasc_monitor.db - the operator's real database. Some tests start the app
(TestClient(app)) and its lifespan calls init_db(), and the SQLite engine
hooks set PRAGMAs such as journal_mode=WAL on connect. Without this file a
test run could therefore open and modify the real database.

conftest.py is imported before any test module, so pointing the URL at a
per-session temp file here guarantees no test can reach the default DB.
The scheduler lock and periodic scheduler are kept out of the way too.
"""
import os
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="iasc_tests_"))
os.environ["IACS_DATABASE_URL"] = f"sqlite:///{_TMP / 'test_default.db'}"
os.environ.setdefault("IACS_REVIEW_ENABLED", "false")
# periodic reviews at upload time (app.review_trigger) run in a background thread;
# off for the suite - tests/test_review_on_upload.py switches it on
os.environ.setdefault("IACS_REVIEW_ON_UPLOAD", "false")
os.environ.setdefault("IACS_SCHEDULER_LOCK", str(_TMP / "scheduler.lock"))


def _ensure_sample_pcaps() -> None:
    """Some tests ingest sample_data/*.pcap. They are generated (and shipped)
    by sample_data/generate_sample_pcap.py; regenerate if a checkout lacks them."""
    import subprocess
    import sys
    root = Path(__file__).resolve().parent.parent
    wanted = [root / "sample_data" / n for n in ("modbus_sample.pcap", "multi_protocol_sample.pcap")]
    if all(w.exists() for w in wanted):
        return
    subprocess.run([sys.executable, str(root / "sample_data" / "generate_sample_pcap.py")],
                   cwd=root, check=True, capture_output=True)


def pytest_sessionstart(session):
    _ensure_sample_pcaps()
    real = Path(__file__).resolve().parent.parent / "iasc_monitor.db"
    session.config._iasc_real_db_mtime = real.stat().st_mtime_ns if real.exists() else None


def pytest_sessionfinish(session, exitstatus):
    """Fail loudly if anything touched the real database anyway."""
    real = Path(__file__).resolve().parent.parent / "iasc_monitor.db"
    before = getattr(session.config, "_iasc_real_db_mtime", None)
    after = real.stat().st_mtime_ns if real.exists() else None
    if before != after or (real.with_name(real.name + "-wal")).exists():
        session.exitstatus = 1
        print(f"\nERROR: test run modified {real} (mtime {before} -> {after})")


# ---------------------------------------------------------------------------
# Multi-site phase 1: every non-log upload route requires ``site``.  Tests
# written before sites existed exercise other behaviour, so TestClient POSTs
# to those routes that do not name a site are sent to the Default site
# (``site=default``; /attestation gets it as a form field).  Tests that check
# the site requirement itself opt out with @pytest.mark.no_auto_site.
# Phase 3: log routes (optional ``site`` = map unknown devices) get
# site=default too, so pre-routing tests keep their events in Default.
# Helpers for explicit use live in tests/_site_util.py.
# ---------------------------------------------------------------------------
import pytest  # noqa: E402


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "no_auto_site: do not add site=default to upload requests")


_AUTO_SITE = {"on": True}


def _install_auto_site() -> None:
    try:
        from starlette.testclient import TestClient
    except ImportError:  # pragma: no cover
        return
    if getattr(TestClient.request, "_iasc_auto_site", False):
        return
    from _site_util import DEFAULT_SITE, is_log_route, needs_site

    orig = TestClient.request

    def request_with_site(self, method, url, *args, **kwargs):
        u = str(url)
        if _AUTO_SITE["on"] and method.upper() == "POST" and "site=" not in u.partition("?")[2]:
            path = u.split("?", 1)[0]
            if path.endswith("/attestation"):
                data = kwargs.get("data")
                if isinstance(data, dict) and "site" not in data:
                    kwargs["data"] = {**data, "site": DEFAULT_SITE}
            elif needs_site(path) or is_log_route(path):
                params = kwargs.get("params")
                if params is None or isinstance(params, dict):
                    if "site" not in (params or {}):
                        kwargs["params"] = {**(params or {}), "site": DEFAULT_SITE}
        return orig(self, method, url, *args, **kwargs)

    request_with_site._iasc_auto_site = True
    TestClient.request = request_with_site


_install_auto_site()  # session-wide (also covers module-scoped seed fixtures)


@pytest.fixture(autouse=True)
def _auto_default_site(request):
    if request.node.get_closest_marker("no_auto_site"):
        _AUTO_SITE["on"] = False
        try:
            yield
        finally:
            _AUTO_SITE["on"] = True
    else:
        yield

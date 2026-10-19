"""config_auto_firmware_upgrade (owner 2026-10-19): FortiGuard automatic firmware upgrades on an
OT firewall are a change-control concern - low, SR 7.6."""
import pytest

from tests.test_mfa_coverage import api_ctx, _by, _upload, CFG  # same harness

FG = """config system fortiguard
    set service-account-id "it@example.test"
    set auto-firmware-upgrade {STATE}
    set auto-firmware-upgrade-day sunday
    set auto-firmware-upgrade-start-hour 2
    set auto-firmware-upgrade-end-hour 4
end
"""


@pytest.fixture
def api(tmp_path, monkeypatch):
    with api_ctx(tmp_path, monkeypatch) as x:
        yield x


def test_enabled_auto_upgrade_is_a_low_finding_with_the_window(api):
    c, sid = api
    _upload(c, CFG.replace("{CM}", FG.replace("{STATE}", "enable")))
    by = _by(c, sid)
    f = by["config_auto_firmware_upgrade"][0]
    assert f["severity"] == "low" and f["detail"]["upgrade_window"] == "sunday 2:00-4:00" and "sunday" in f["detail"]["reason"]
    assert f["detail"]["auto_firmware_upgrade"] == "enable"


def test_disabled_or_absent_is_silent(api):
    c, sid = api
    _upload(c, CFG.replace("{CM}", FG.replace("{STATE}", "disable")))
    assert "config_auto_firmware_upgrade" not in _by(c, sid)
    _upload(c, CFG.replace("{CM}", ""), name="FGT-MFA-2")
    assert not [f for f in _by(c, sid).get("config_auto_firmware_upgrade", []) if f["device_name"] == "FGT-MFA-2"]


def test_registered_everywhere():
    from app.models import CHECK_TYPE_REFERENCE
    from app.explain import C as EXPLAIN
    from app import writeup as wu
    from app.config_store import CHECK_SECTIONS
    from app.parsers.forti_config_parser import FORTIGATE_CONFIG_CHECKS
    n = "config_auto_firmware_upgrade"
    assert n in CHECK_TYPE_REFERENCE and n in FORTIGATE_CONFIG_CHECKS and n in EXPLAIN and n in CHECK_SECTIONS and n in wu.FORTI and n in wu.CIS
    assert "# was enable (window sunday 2:00-4:00)" in wu.forti_example(n, {"upgrade_window": "sunday 2:00-4:00"})

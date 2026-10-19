"""NTP sources placed against the firewall's interface networks (owner 2026-10-19)."""
import pytest

from tests.test_mfa_coverage import api_ctx, _by, _upload, CFG   # port1 10.10.1.0/24 (no label), wan1 public

NTP = """config router static
    edit 1
        set dst 10.168.0.0 255.255.0.0
        set gateway 10.10.1.254
        set device "port1"
    next
end
config system ntp
    set ntpsync enable
    set type custom
    config ntpserver
{SERVERS}    end
    set server-mode {MODE}
    set interface "port1"
end
"""


def _srv(*names):
    return "".join(f'        edit {i}\n            set server "{n}"\n        next\n' for i, n in enumerate(names, 1))


@pytest.fixture
def api(tmp_path, monkeypatch):
    with api_ctx(tmp_path, monkeypatch) as x:
        yield x


def _label_port1(c, sid, level):
    from app.models import FirewallInterface
    import app.main as main_mod
    from app.db import get_db
    s = next(main_mod.app.dependency_overrides[get_db]())
    for i in s.query(FirewallInterface).filter(FirewallInterface.name == "port1"):
        i.purdue_level = level
    s.commit(); s.close()


def test_local_pools_and_routed_servers_are_placed(api):
    c, sid = api
    _upload(c, CFG.replace("{CM}", NTP.replace("{SERVERS}", _srv("10.10.1.5", "0.pool.ntp.org", "10.168.1.5", "8.8.8.8")).replace("{MODE}", "disable")))
    f = _by(c, sid)["config_ntp_fortiguard"][0]
    kinds = {p["server"]: (p["kind"], p["where"]) for p in f["detail"]["servers"]}
    assert kinds["10.10.1.5"] == ("local", "port1")
    assert kinds["10.168.1.5"] == ("internal", "static route 10.168.0.0/16 via port1")
    assert kinds["0.pool.ntp.org"] == ("external", "name") and kinds["8.8.8.8"] == ("external", "public address")
    assert f["severity"] == "medium" and f["detail"]["has_wan_leg"] is True          # wan1 is a WAN leg
    assert f["title"].startswith("NTP from external source(s): 0.pool.ntp.org, 8.8.8.8 (also inside: 10.10.1.5, 10.168.1.5)")
    assert f["detail"]["server_mode"] is False


def test_internal_only_is_silent_and_level_is_named(api):
    c, sid = api
    _upload(c, CFG.replace("{CM}", NTP.replace("{SERVERS}", _srv("10.10.1.5")).replace("{MODE}", "enable")))
    assert "config_ntp_fortiguard" not in _by(c, sid)


def test_pools_only_serving_ot_interfaces_is_high(api):
    c, sid = api
    _upload(c, CFG.replace("{CM}", NTP.replace("{SERVERS}", _srv("0.pool.ntp.org", "1.pool.ntp.org")).replace("{MODE}", "enable")))
    _label_port1(c, sid, 1)
    _upload(c, CFG.replace("{CM}", NTP.replace("{SERVERS}", _srv("0.pool.ntp.org", "1.pool.ntp.org")).replace("{MODE}", "enable")))
    f = _by(c, sid)["config_ntp_fortiguard"][0]
    assert f["severity"] == "high" and f["detail"]["served_ot_interfaces"] == ["port1"] and "entirely on the Internet" in f["detail"]["severity_reason"]


def test_fortiguard_with_ot_server_mode_steps_up(api):
    c, sid = api
    fg = NTP.replace("{SERVERS}", "").replace("set type custom", "set type fortiguard").replace("{MODE}", "enable")
    _upload(c, CFG.replace("{CM}", fg))
    _label_port1(c, sid, 1)
    _upload(c, CFG.replace("{CM}", fg))
    f = _by(c, sid)["config_ntp_fortiguard"][0]
    assert f["severity"] == "low" and "serves time to OT interfaces port1" in f["detail"]["severity_reason"]

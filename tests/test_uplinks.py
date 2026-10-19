"""Uplink evidence, the link-monitor note and remote-site NTP placement (owner 2026-10-19)."""
import pytest

from tests.test_mfa_coverage import api_ctx, _by, _upload, CFG

UPLINK = """config system link-monitor
    edit "wan1_monitor"
        set srcintf "wan1"
        set server {SERVERS}
        set interval 1000
    next
end
config router static
    edit 1
        set dst 10.250.1.0 255.255.255.0
        set device "ipsecgw"
    next
    edit 2
        set dst 10.250.1.0 255.255.255.0
        set distance 200
        set blackhole enable
    next
    edit 3
        set gateway 203.0.113.1
        set device "wan1"
    next
end
config vpn ipsec phase1-interface
    edit "ipsecgw"
        set interface "wan1"
        set remote-gw 198.51.100.7
        set psksecret ENC x
    next
end
config system ntp
    set ntpsync enable
    set type custom
    config ntpserver
        edit 1
            set server "10.250.1.5"
        next
        edit 2
            set server "0.pool.ntp.org"
        next
    end
end
"""


@pytest.fixture
def api(tmp_path, monkeypatch):
    with api_ctx(tmp_path, monkeypatch) as x:
        yield x


def test_public_only_probes_are_an_info_finding_with_evidence(api):
    c, sid = api
    _upload(c, CFG.replace("{CM}", UPLINK.replace("{SERVERS}", '"8.8.8.8" "8.8.4.4"')))
    by = _by(c, sid)
    f = by["config_link_monitor_external"][0]
    assert f["severity"] == "info" and f["detail"]["monitors"] == [{"interface": "wan1", "server": "8.8.8.8"}, {"interface": "wan1", "server": "8.8.4.4"}]
    ev = c.get("/findings", params={"site_id": sid, "check_name": "config_link_monitor_external"}).json()
    assert ev
    from app.parsers.forti_config_parser import parse_forti_block, _config_evidence, _extract_dns_ntp
    parsed = parse_forti_block(CFG.replace("{CM}", UPLINK.replace("{SERVERS}", '"8.8.8.8" "8.8.4.4"')))
    secs = _config_evidence(parsed, [], _extract_dns_ntp(parsed), [], {})
    rows = {r["setting"]: r["value"] for s in secs for r in s["rows"]}
    assert rows["Uplink monitoring (system link-monitor)"] == "wan1 -> 8.8.8.8, 8.8.4.4"
    assert rows["Default routes (router static)"] == "wan1 (distance 10)"


def test_internal_probe_silences_it(api):
    c, sid = api
    _upload(c, CFG.replace("{CM}", UPLINK.replace("{SERVERS}", '"8.8.8.8" "203.0.113.1"')))   # ISP gateway (not global: TEST-NET)
    assert "config_link_monitor_external" not in _by(c, sid)


def test_ntp_server_behind_the_tunnel_is_a_remote_site(api):
    c, sid = api
    _upload(c, CFG.replace("{CM}", UPLINK.replace("{SERVERS}", '"8.8.8.8"')))
    f = _by(c, sid)["config_ntp_fortiguard"][0]
    place = {p["server"]: p for p in f["detail"]["servers"]}
    assert place["10.250.1.5"]["kind"] == "remote" and place["10.250.1.5"]["where"] == "remote site via ipsecgw (static route 10.250.1.0/24)"
    assert place["0.pool.ntp.org"]["kind"] == "external" and "also inside: 10.250.1.5" in f["title"]
    assert f["severity"] == "medium"                                     # external pool with a WAN leg, inside source present


def test_registered_everywhere():
    from app.models import CHECK_TYPE_REFERENCE
    from app.explain import C as EXPLAIN
    from app import writeup as wu
    from app.config_store import CHECK_SECTIONS
    from app.parsers.forti_config_parser import FORTIGATE_CONFIG_CHECKS
    n = "config_link_monitor_external"
    assert n in CHECK_TYPE_REFERENCE and n in FORTIGATE_CONFIG_CHECKS and n in EXPLAIN and n in CHECK_SECTIONS and n in wu.FORTI and n in wu.CIS

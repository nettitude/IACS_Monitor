"""Declared management networks (app/parsers/mgmt_networks.py): declarations,
the management context, the re-judged config checks, the network / rule /
chain checks that honour them, targeted re-checks and the API."""
import textwrap

import pytest

from app.models import (
    ApprovedHost, Baseline, Finding, Firewall, FirewallInterface, Host, ManagementNetwork,
    SwitchVlan,
)
from app.parsers import alert_engine as ae
from app.parsers import mgmt_networks as mg
from app.parsers.forti_config_parser import ingest_fortigate_config
from app.parsers.site_scope import analysis_site
from app.sites import ingest_site
from tests.test_access_paths import _ADDR_SVC, _site, db  # noqa: F401
from tests.test_access_paths_overlay import _host, _sess

CFG = _ADDR_SVC + """
    config system admin
        edit "admin"
            set accprofile "super_admin"
            set trusthost1 10.4.0.0 255.255.255.0
            set trusthost2 10.9.0.0 255.255.255.0
        next
    end
    config system interface
        edit "p_it"
            set vdom "root"
            set ip 10.4.0.1 255.255.255.0
            set allowaccess ping https ssh
        next
        edit "p_ot"
            set vdom "root"
            set ip 10.2.0.1 255.255.255.0
            set allowaccess ping
        next
        edit "mgmt1"
            set vdom "root"
            set ip 10.9.0.1 255.255.255.0
            set allowaccess https ssh
        next
        edit "port9"
            set vdom "root"
            set alias "OOB-NET"
            set ip 10.8.0.1 255.255.255.0
            set allowaccess https
        next
        edit "vl99"
            set vdom "root"
            set type vlan
            set interface "p_ot"
            set vlanid 99
            set ip 10.99.0.1 255.255.255.0
            set allowaccess ping
        next
    end
    config firewall policy
        edit 5
            set name "it-ssh-ot"
            set srcintf "p_it"
            set dstintf "p_ot"
            set srcaddr "it_host"
            set dstaddr "ot_host"
            set action accept
            set schedule "always"
            set service "SSHX"
        next
    end
"""
LEVELS = {"p_it": 3, "p_ot": 2, "mgmt1": 3, "port9": 3, "vl99": 2}
IT_HOST, OT_HOST = "10.4.0.10", "10.2.0.20"


def _plant(db, name="Mgmt plant", fw="MG-FGT", findings=True):
    sid = _site(db, name)
    with ingest_site(db, sid):
        ingest_fortigate_config(textwrap.dedent(CFG), db, firewall_name=fw,
                                generate_findings=findings)
    db.flush()
    f = db.query(Firewall).filter(Firewall.name == fw, Firewall.site_id == sid).one()
    for fi in db.query(FirewallInterface).filter(FirewallInterface.firewall_id == f.id):
        if fi.name in LEVELS:
            fi.purdue_level = LEVELS[fi.name]
    db.commit()
    return sid, f


def _open(db, sid, check):
    return db.query(Finding).filter(Finding.site_id == sid, Finding.check_name == check,
                                    Finding.status == "open").all()


def _declare(db, sid, **kw):
    with analysis_site(db, sid):
        row, created = mg.declare(db, sid, **kw)
    db.commit()
    return row


# ------------------------------------------------------------ declarations --
def test_declare_validation_and_keys(db):
    sid, fw = _plant(db, findings=False)
    with analysis_site(db, sid):
        r, created = mg.declare(db, sid, kind="subnet", cidr="10.9.0.7/24", label="OOB")
        assert created and r.cidr == "10.9.0.0/24" and r.key == "subnet:10.9.0.0/24"
        with pytest.raises(mg.MgmtError) as e:
            mg.declare(db, sid, kind="subnet", cidr="10.9.0.0/24")
        assert e.value.status == 409
        for bad in ({"kind": "subnet", "cidr": "0.0.0.0/0"}, {"kind": "subnet", "cidr": "nope"},
                    {"kind": "host", "cidr": "10.1.0.0/24"}, {"kind": "host", "cidr": "10.1.0.5", "role": "hmi"},
                    {"kind": "vlan", "vlan_id": 5000}, {"kind": "name", "name": ""}, {"kind": "zone"}):
            with pytest.raises(mg.MgmtError):
                mg.declare(db, sid, **bad)
        with pytest.raises(mg.MgmtError) as e:
            mg.declare(db, sid, kind="name", name="p_it", firewall_id=9999)
        assert e.value.status == 404
        h, _ = mg.declare(db, sid, kind="host", cidr="10.4.0.10")
        assert h.cidr == "10.4.0.10/32" and h.role == "admin_ws"
        # a name declaration is an upsert: reclassifying flips it
        n1, c1 = mg.declare(db, sid, kind="name", name="Port9", firewall_id=fw.id)
        n2, c2 = mg.declare(db, sid, kind="name", name="port9", firewall_id=fw.id, is_management=False)
        assert c1 and not c2 and n1.id == n2.id and n2.is_management is False
        assert n2.key == f"name:{fw.id}:port9"


def test_context_sources_scope_and_names(db):
    sid, fw = _plant(db, findings=False)
    _declare(db, sid, kind="subnet", cidr="10.9.0.0/24")
    _declare(db, sid, kind="host", cidr="10.4.0.10", role="jump_host")
    _declare(db, sid, kind="vlan", vlan_id=99)
    _declare(db, sid, kind="name", name="OOB-NET", firewall_id=fw.id)
    _declare(db, sid, kind="name", name="mgmt1", is_management=False)        # every firewall
    h = _host(db, sid, "10.77.0.5", 3)
    h.vlan = "99"
    db.commit()
    with analysis_site(db, sid):
        ctx = mg.build_context(db)
    assert ctx.is_admin_ip("10.9.0.200") and "management network" in ctx.source_of("10.9.0.200")
    assert "jump host" in ctx.source_of("10.4.0.10")
    assert ctx.is_admin_ip("10.99.0.33")              # VLAN 99 interface subnet
    assert ctx.is_admin_ip("10.77.0.5")               # host the switches put on VLAN 99
    assert ctx.is_admin_ip("10.8.0.9")                # subnet of port9, declared by its alias
    assert not ctx.is_admin_ip("10.4.0.11") and not ctx.is_admin_ip("bogus")
    assert ctx.scope_is_mgmt("10.9.0.0/25,10.4.0.10/32")
    assert ctx.scope_is_mgmt("range:10.9.0.1-10.9.0.9")
    assert not ctx.scope_is_mgmt("10.9.0.0/23") and not ctx.scope_is_mgmt("any")
    assert not ctx.scope_is_mgmt("OBJ_unknown")
    assert ctx.name_class(fw.id, "port9", "OOB-NET") is True
    assert ctx.name_class(fw.id, "mgmt1") is False
    assert ctx.name_class(fw.id, "p_it") is None


# --------------------------------------------------------- config checks --
def test_config_zone_check_per_interface_and_reclassification(db):
    sid, fw = _plant(db)
    found = {f.detail["interface"]: f for f in _open(db, sid, mg.CHECK_CFG_ZONE)}
    # p_it (no keyword) and port9 (alias OOB-NET is not a config keyword); mgmt1 is
    # a management zone by name; p_ot / vl99 allow no admin access
    assert set(found) == {"p_it", "port9"}
    assert found["p_it"].source_ref == f"config:{fw.id}:{mg.CHECK_CFG_ZONE}:p_it"
    # reclassify port9 -> closes its finding without a re-upload
    _declare(db, sid, kind="name", name="OOB-NET", firewall_id=fw.id)
    with analysis_site(db, sid):
        mg.review_config_all(db)
    db.commit()
    assert {f.detail["interface"] for f in _open(db, sid, mg.CHECK_CFG_ZONE)} == {"p_it"}
    closed = db.query(Finding).filter(Finding.source_ref == found["port9"].source_ref).one()
    assert closed.status == "closed" and closed.notes.startswith("Auto-resolved: management")
    # "mgmt1 is NOT a management zone" -> raised although the name says mgmt
    _declare(db, sid, kind="name", name="mgmt1", firewall_id=fw.id, is_management=False)
    with analysis_site(db, sid):
        mg.review_config_all(db)
    db.commit()
    assert {f.detail["interface"] for f in _open(db, sid, mg.CHECK_CFG_ZONE)} == {"p_it", "mgmt1"}
    # remove the port9 declaration -> the same finding re-opens
    row = db.query(ManagementNetwork).filter(ManagementNetwork.name == "OOB-NET").one()
    with analysis_site(db, sid):
        mg.delete(db, row.id)
        mg.review_config_all(db)
    db.commit()
    again = db.query(Finding).filter(Finding.source_ref == found["port9"].source_ref).one()
    assert again.status == "open" and again.id == found["port9"].id


def test_reingest_keeps_mgmt_findings_and_stores_trusthosts(db):
    sid, fw = _plant(db)
    assert fw.admin_trusthosts == [{"username": "admin", "accprofile": "super_admin",
                                   "trusted_hosts": ["10.4.0.0/24", "10.9.0.0/24"]}]
    before = {f.id for f in _open(db, sid, mg.CHECK_CFG_ZONE)}
    with ingest_site(db, sid):
        ingest_fortigate_config(textwrap.dedent(CFG), db, firewall_name="MG-FGT",
                                generate_findings=True)
    db.commit()
    assert {f.id for f in _open(db, sid, mg.CHECK_CFG_ZONE)} == before   # not auto-resolved


def test_trusthost_outside_mgmt_only_judged_once_declared(db):
    sid, fw = _plant(db)
    # a baseline admin host alone does not describe the management networks
    b = Baseline(name="b", site_id=sid, is_active=True)
    db.add(b)
    db.flush()
    db.add(ApprovedHost(baseline_id=b.id, ip="10.9.0.5", role="admin_ws"))
    db.commit()
    with analysis_site(db, sid):
        mg.review_config_all(db)
    db.commit()
    assert _open(db, sid, mg.CHECK_TRUSTHOST) == []
    _declare(db, sid, kind="subnet", cidr="10.9.0.0/24")
    with analysis_site(db, sid):
        mg.review_config_all(db)
    db.commit()
    [f] = _open(db, sid, mg.CHECK_TRUSTHOST)
    assert f.detail["trusthost"] == "10.4.0.0/24" and f.checklist_id == "9.5"
    _declare(db, sid, kind="subnet", cidr="10.4.0.0/24")
    with analysis_site(db, sid):
        mg.review_config_all(db)
    db.commit()
    assert _open(db, sid, mg.CHECK_TRUSTHOST) == []


def test_not_management_clears_mgmt_only_flag(db):
    sid, fw = _plant(db, findings=False)
    m1 = db.query(FirewallInterface).filter(FirewallInterface.firewall_id == fw.id,
                                            FirewallInterface.name == "mgmt1").one()
    assert m1.is_mgmt_only is True                    # name heuristic at ingest
    _declare(db, sid, kind="name", name="mgmt1", firewall_id=fw.id, is_management=False)
    assert mg.apply_mgmt_only_overrides(db, fw.id) == 1
    db.commit()
    assert m1.is_mgmt_only is False
    with ingest_site(db, sid):                        # a re-ingest keeps it routed
        ingest_fortigate_config(textwrap.dedent(CFG), db, firewall_name="MG-FGT")
    db.commit()
    db.refresh(m1)
    assert m1.is_mgmt_only is False


# ------------------------------------------------ network / rule checks --
def _mgmt_traffic(db, sid):
    it, ot = _host(db, sid, IT_HOST, 3), _host(db, sid, OT_HOST, 2)
    b = Baseline(name="b", site_id=sid, is_active=True)
    db.add(b)
    db.flush()
    db.add(ApprovedHost(baseline_id=b.id, ip="10.9.0.5", role="admin_ws"))
    _sess(db, it, ot, 40000, 22)
    db.commit()
    return it, ot


def test_pcap_checks_honour_trusted_hosts_and_networks(db):
    sid, fw = _plant(db, findings=False)
    _mgmt_traffic(db, sid)
    ae.run_periodic_reviews(db, site_id=sid)
    assert [f.detail["src_ip"] for f in _open(db, sid, "mgmt_access_from_wrong_zone")] == [IT_HOST]
    assert [f.detail["src_ip"] for f in _open(db, sid, "session_mgmt_from_non_admin")] == [IT_HOST]
    _declare(db, sid, kind="subnet", cidr="10.4.0.0/24")
    ae.run_periodic_reviews(db, site_id=sid, only=mg.MGMT_REVIEWS)
    assert _open(db, sid, "mgmt_access_from_wrong_zone") == []
    assert _open(db, sid, "session_mgmt_from_non_admin") == []


def test_not_restricted_counts_management_sources_as_one_zone(db):
    sid, fw = _plant(db, findings=False)
    it, ot = _mgmt_traffic(db, sid)
    other = _host(db, sid, "10.30.0.7", 2)
    _sess(db, other, ot, 40001, 443)
    db.commit()
    ae.run_periodic_reviews(db, site_id=sid)
    [f] = _open(db, sid, "mgmt_access_not_restricted")
    assert f.detail["src_purdue_levels"] == [2, 3]
    _declare(db, sid, kind="host", cidr=IT_HOST)
    _declare(db, sid, kind="host", cidr="10.30.0.7")
    ae.run_periodic_reviews(db, site_id=sid, only=mg.MGMT_REVIEWS)
    assert _open(db, sid, "mgmt_access_not_restricted") == []


def test_rule_mgmt_wrong_zone_exempts_management_sources(db):
    sid, fw = _plant(db, findings=False)
    ae.run_periodic_reviews(db, site_id=sid)
    [f] = _open(db, sid, "rule_mgmt_wrong_zone")
    assert f.detail["policy_id"] == "5"
    # declaring the source zone a management zone is the sanctioned path ...
    row = _declare(db, sid, kind="name", name="p_it", firewall_id=fw.id)
    ae.run_periodic_reviews(db, site_id=sid, only=mg.MGMT_REVIEWS)
    assert _open(db, sid, "rule_mgmt_wrong_zone") == []
    # ... and so is a source address inside the management networks
    with analysis_site(db, sid):
        mg.delete(db, row.id)
    db.commit()
    ae.run_periodic_reviews(db, site_id=sid, only=mg.MGMT_REVIEWS)
    assert len(_open(db, sid, "rule_mgmt_wrong_zone")) == 1
    _declare(db, sid, kind="host", cidr=IT_HOST)
    ae.run_periodic_reviews(db, site_id=sid, only=mg.MGMT_REVIEWS)
    assert _open(db, sid, "rule_mgmt_wrong_zone") == []


def test_targeted_run_only_runs_the_named_reviews(db):
    sid, fw = _plant(db, findings=False)
    ae.run_periodic_reviews(db, site_id=sid)
    full = dict(ae._last_review_info_by_site[sid])
    stats = ae.run_periodic_reviews(db, site_id=sid, only={"review_mgmt_access_from_wrong_zone"})
    assert "review_mgmt_access_from_wrong_zone" in stats
    assert "review_cleartext_protocols" not in stats and "review_chain_it_ot_bypass" not in stats
    assert ae._last_review_info_by_site[sid] == full  # a targeted run is not "the last run"
    # asking for one rule twin runs the whole twin family (related_checks)
    stats = ae.run_periodic_reviews(db, site_id=sid, only={"review_rule_mgmt_wrong_zone"})
    assert "review_rule_it_ot_bypass" in stats


# -------------------------------------------------------------- recheck --
def test_recheck_reports_before_after_and_closes_realtime(db):
    sid, fw = _plant(db)
    db.add(Finding(site_id=sid, check_name="auth_from_non_admin_host", category="real_time",
                   severity="high", status="open", title="admin login", source_ref="rt-1",
                   detail={"src_ip": "10.4.0.10"}))
    db.commit()
    r = mg.recheck(db, sid)
    assert r["after"]["auth_from_non_admin_host"] == 1 and r["closed"] == 0
    _declare(db, sid, kind="subnet", cidr="10.4.0.0/24")
    _declare(db, sid, kind="name", name="OOB-NET", firewall_id=fw.id)
    r = mg.recheck(db, sid)
    assert r["realtime_closed"] == 1
    # p_it's subnet is now a management network, port9 is declared by its alias
    assert r["before"][mg.CHECK_CFG_ZONE] == 2 and r["after"][mg.CHECK_CFG_ZONE] == 0
    assert r["closed"] >= 3 and "10.4.0.0/24" in r["context"]["management_networks"]


# ------------------------------------------------------------ inventory --
def test_inventory_suggestions_and_fix_options(db):
    sid, fw = _plant(db, findings=True)
    db.add(SwitchVlan(site_id=sid, device_name="SW1", vlan_id=99, vlan_name="MGMT_VLAN"))
    db.add(SwitchVlan(site_id=sid, device_name="SW1", vlan_id=20, vlan_name="OPS"))
    h = _host(db, sid, IT_HOST, 3)
    h.vlan = "20"
    db.commit()
    with analysis_site(db, sid):
        inv = {i["name"]: i for i in mg.interface_inventory(db)}
        assert inv["mgmt1"]["is_management"] and inv["mgmt1"]["declared"] is None
        assert inv["p_it"]["management_access"] and not inv["p_it"]["is_management"]
        vl = {v["vlan_id"]: v for v in mg.vlan_inventory(db)}
        assert vl[99]["subnets"] == ["10.99.0.0/24"] and vl[99]["suggested"]
        assert vl[20]["hosts"] == 1 and not vl[20]["suggested"]
        sugg = mg.suggestions(db)
        assert {"kind": "name", "name": "mgmt1"}.items() <= next(
            s for s in sugg if s["kind"] == "name").items()
        assert any(s["kind"] == "name" and s["name"] == "port9" for s in sugg)   # alias OOB-NET
        assert any(s["kind"] == "vlan" and s["vlan_id"] == 99 for s in sugg)
        cfg_f = next(f for f in _open(db, sid, mg.CHECK_CFG_ZONE) if f.detail["interface"] == "p_it")
        opts = mg.fix_options(db, cfg_f)["options"]
        assert opts[0]["kind"] == "name" and opts[0]["name"] == "p_it" and opts[0]["recommended"]
        assert "10.4.0.0/24 becomes a management network" in opts[0]["label"]
        sess_f = Finding(site_id=sid, check_name="session_mgmt_from_non_admin", category="periodic_review",
                         severity="medium", status="open", title="x", detail={"src_ip": IT_HOST})
        kinds = [(o["kind"], o.get("cidr") or o.get("vlan_id")) for o in mg.fix_options(db, sess_f)["options"]]
        assert ("host", "10.4.0.10/32") in kinds and ("subnet", "10.4.0.0/24") in kinds
        assert ("vlan", 20) in kinds
        other = Finding(site_id=sid, check_name="cleartext_protocol", category="periodic_review",
                        severity="low", status="open", title="x", detail={})
        r = mg.fix_options(db, other)
        assert r["options"] == [] and not r["applies"]


# ------------------------------------------------------------ engineering --
def test_engineering_sources_count_only_toward_ot(db):
    sid, fw = _plant(db, findings=True)
    _declare(db, sid, kind="host", cidr=IT_HOST, role="engineering_ws")
    _declare(db, sid, kind="subnet", cidr="10.4.0.0/24", purpose="engineering")
    with analysis_site(db, sid):
        ctx = mg.build_context(db)
    assert ctx.has_eng_sources and not ctx.has_mgmt_sources and not ctx.declared_sources
    assert ctx.is_admin_ip(IT_HOST, ot=True) and ctx.is_engineering_ip(IT_HOST)
    assert not ctx.is_admin_ip(IT_HOST)                       # not for infrastructure admin
    assert "engineering workstation" in ctx.source_of(IT_HOST, ot=True)
    assert ctx.scope_is_mgmt("10.4.0.0/25", ot=True) and not ctx.scope_is_mgmt("10.4.0.0/25")
    # p_it lies in the engineering network: still not a management zone for firewall admin
    with analysis_site(db, sid):
        mg.review_config_all(db)
    db.commit()
    f = next(f for f in _open(db, sid, mg.CHECK_CFG_ZONE) if f.detail["interface"] == "p_it")
    assert "engineering network" in f.detail["classification"]
    assert _open(db, sid, mg.CHECK_TRUSTHOST) == []            # nothing management declared


def test_engineering_zone_name_and_purpose_upsert(db):
    sid, fw = _plant(db, findings=False)
    with analysis_site(db, sid):
        r, created = mg.declare(db, sid, kind="name", name="p_it", firewall_id=fw.id, purpose="engineering")
        assert created and r.purpose == "engineering"
        ctx = mg.build_context(db)
        assert ctx.name_class(fw.id, "p_it", ot=True) is True
        assert ctx.name_class(fw.id, "p_it") is False         # not a management zone
        v, c = mg.declare(db, sid, kind="vlan", vlan_id=99, purpose="engineering")
        v2, c2 = mg.declare(db, sid, kind="vlan", vlan_id=99, purpose="management")
        assert c and not c2 and v2.id == v.id and v2.purpose == "management"
        with pytest.raises(mg.MgmtError) as e:
            mg.declare(db, sid, kind="vlan", vlan_id=99, purpose="management")
        assert e.value.status == 409
        h, _ = mg.declare(db, sid, kind="host", cidr="10.4.0.20", purpose="engineering")
        assert h.role == "engineering_ws" and h.purpose == "engineering"
        with pytest.raises(mg.MgmtError):
            mg.declare(db, sid, kind="subnet", cidr="10.5.0.0/24", purpose="operations")
    db.commit()
    ae.run_periodic_reviews(db, site_id=sid)
    assert _open(db, sid, "rule_mgmt_wrong_zone") == []      # engineering zone toward OT


def test_baseline_engineering_ws_exempts_ot_management(db):
    sid, fw = _plant(db, findings=False)
    it, ot = _host(db, sid, IT_HOST, 3), _host(db, sid, OT_HOST, 2)
    b = Baseline(name="b", site_id=sid, is_active=True)
    db.add(b)
    db.flush()
    db.add(ApprovedHost(baseline_id=b.id, ip=IT_HOST, role="engineering_ws"))
    _sess(db, it, ot, 40000, 22)
    db.commit()
    ae.run_periodic_reviews(db, site_id=sid)
    for check in ("rule_mgmt_wrong_zone", "mgmt_access_from_wrong_zone", "session_mgmt_from_non_admin"):
        assert _open(db, sid, check) == [], check
    # ... but an engineering workstation managing an IT-side server is not exempt
    srv = _host(db, sid, "10.4.0.99", 3)
    _sess(db, it, srv, 40002, 3389)
    db.commit()
    ae.run_periodic_reviews(db, site_id=sid)
    assert [f.detail["dst_ip"] for f in _open(db, sid, "session_mgmt_from_non_admin")] == ["10.4.0.99"]


def test_engineering_sources_approve_industrial_writes(db):
    from app.models import FortiAnalyzerEvent
    from app.parsers.traffic_findings import _get_approved_engineering_hosts
    sid, fw = _plant(db, findings=False)
    ev = FortiAnalyzerEvent(source_type="syslog_cef", vendor="fortinet", device_name="MG-FGT",
                            log_type="traffic", action="accept", src_ip=IT_HOST, dst_ip=OT_HOST,
                            dst_port=502, site_id=sid)
    db.add(ev)
    db.flush()
    with analysis_site(db, sid):
        assert ae.check_unauth_ot_write(ev, db) is not None     # fail-open: nothing approved
    db.add(Finding(site_id=sid, check_name="unauthorized_industrial_write", category="real_time",
                   severity="critical", status="open", title="write", source_ref="iw-1",
                   detail={"src_ip": IT_HOST}))
    db.commit()
    _declare(db, sid, kind="host", cidr=IT_HOST, role="engineering_ws")
    with analysis_site(db, sid):
        assert ae.check_unauth_ot_write(ev, db) is None
        nets, _macs = _get_approved_engineering_hosts(db)
    assert any(str(n) == "10.4.0.10/32" for n in nets)
    r = mg.recheck(db, sid)
    assert r["after"]["unauthorized_industrial_write"] == 0 and r["realtime_closed"] >= 1
    # a management host is not an engineering source
    _declare(db, sid, kind="host", cidr="10.4.0.11", role="admin_ws")
    ev2 = FortiAnalyzerEvent(source_type="syslog_cef", vendor="fortinet", device_name="MG-FGT",
                             log_type="traffic", action="accept", src_ip="10.4.0.11", dst_ip=OT_HOST,
                             dst_port=102, site_id=sid)
    db.add(ev2)
    db.flush()
    with analysis_site(db, sid):
        f = ae.check_unauth_ot_write(ev2, db)
    assert f is not None and "declared engineering network" in f.detail["description"]


def test_fix_options_put_engineering_first_toward_ot(db):
    sid, fw = _plant(db, findings=False)
    ot = _host(db, sid, OT_HOST, 2)
    mk = lambda check, **d: Finding(site_id=sid, check_name=check, category="periodic_review",  # noqa: E731
                                    severity="medium", status="open", title="x", detail=d)
    with analysis_site(db, sid):
        o = mg.fix_options(db, mk("mgmt_access_from_wrong_zone", src_ip=IT_HOST, dst_ip=OT_HOST))["options"]
        assert o[0]["role"] == "engineering_ws" and o[0]["recommended"]
        assert sum(1 for x in o if x.get("recommended")) == 1
        o = mg.fix_options(db, mk("mgmt_access_from_wrong_zone", src_ip="10.35.0.5", dmz_source=True))["options"]
        assert o[0]["role"] == "jump_host"
        o = mg.fix_options(db, mk("auth_from_non_admin_host", src_ip=IT_HOST))["options"]
        assert all(x.get("purpose", "management") == "management" and x.get("role") != "engineering_ws"
                   for x in o)
        o = mg.fix_options(db, mk("unauthorized_industrial_write", src_ip=IT_HOST))["options"]
        assert o and all(x.get("role", "engineering_ws") == "engineering_ws" and
                         x.get("purpose", "engineering") == "engineering" for x in o)
        o = mg.fix_options(db, mk("rule_mgmt_wrong_zone", firewall_id=fw.id, src_zone="p_it",
                                  src="10.4.0.10/32"))["options"]
        assert o[0]["kind"] == "name" and o[0]["purpose"] == "engineering"
        o = mg.fix_options(db, mk("session_mgmt_from_non_admin", src_ip=IT_HOST, dst_ip="10.4.0.99"))["options"]
        assert o[0]["role"] == "admin_ws"                     # IT-side destination


# ------------------------------------------------------------------- API --
from tests.test_access_path_tags import api  # noqa: E402,F401


def test_management_api_round_trip(api):
    c = api
    sid = c.post("/sites", json={"name": "Api mgmt", "code": "apimg"}).json()["id"]
    r = c.post("/ingest/fortigate-config",
               params={"site": "apimg", "firewall_name": "MG-FGT", "generate_findings": "true"},
               files={"file": ("mg.conf", textwrap.dedent(CFG).encode(), "text/plain")})
    assert r.status_code == 200, r.text
    fs = c.get("/findings", params={"site_id": sid, "status": "open", "limit": 500}).json()
    fs = fs if isinstance(fs, list) else fs.get("findings") or fs.get("items")
    target = next(f for f in fs if f["check_name"] == mg.CHECK_CFG_ZONE
                  and (f.get("detail") or {}).get("interface") == "p_it")
    opts = c.get("/management/fix-options", params={"finding_id": target["id"]}).json()
    rec = next(o for o in opts["options"] if o.get("recommended"))
    body = {k: v for k, v in rec.items() if k not in ("label", "recommended")}
    r = c.post("/management/networks", json={**body, "finding_id": target["id"], "created_by": "op"})
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["site_id"] == sid and out["created"] and out["declaration"]["finding_id"] == target["id"]
    assert out["recheck"]["closed"] >= 1
    assert out["recheck"]["after"][mg.CHECK_CFG_ZONE] == out["recheck"]["before"][mg.CHECK_CFG_ZONE] - 1
    view = c.get("/management/networks", params={"site_id": sid}).json()
    [d] = view["declarations"]
    assert d["kind"] == "name" and d["matches"][0]["interface"] == "p_it"
    assert any(s["network"] == "10.4.0.0/24" for s in view["sources"])
    assert c.post("/management/networks", params={"site_id": sid},
                  json={"kind": "subnet", "cidr": "10.0.0.0/4"}).status_code == 422
    assert c.post("/management/networks", params={"site_id": sid},
                  json={"kind": "vlan", "vlan_id": 99, "recheck": False}).status_code == 201
    assert c.post("/management/networks", params={"site_id": sid},
                  json={"kind": "vlan", "vlan_id": 99}).status_code == 409
    r = c.delete(f"/management/networks/{d['id']}", params={"site_id": sid})
    assert r.status_code == 200 and r.json()["recheck"]["opened"] >= 1
    assert c.delete(f"/management/networks/{d['id']}", params={"site_id": sid}).status_code == 404
    assert c.get("/management/fix-options", params={"finding_id": 999999}).status_code == 404
    r = c.post("/management/recheck", params={"site_id": sid})
    assert r.status_code == 200 and mg.CHECK_CFG_ZONE in r.json()["after"]


def test_report_lists_declarations_with_purpose(db):
    import generate_report as gr
    sid, fw = _plant(db, findings=False)
    _declare(db, sid, kind="host", cidr=IT_HOST, role="engineering_ws", created_by="op")
    _declare(db, sid, kind="name", name="mgmt1", firewall_id=fw.id, is_management=False)
    data = gr.collect_report_data(db, site_id=sid)
    mn = {m["what"]: m for m in data["management_networks"]}
    assert mn["10.4.0.10/32"]["purpose"] == "engineering"
    assert mn["10.4.0.10/32"]["detail"] == "engineering workstation"
    assert mn["mgmt1 on MG-FGT"]["purpose"] is None
    text = " ".join(getattr(f, "text", "") for f in gr.build_management_networks(data))
    assert "Engineering" in text and "Management &amp; Engineering" in text

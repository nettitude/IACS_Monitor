"""Declared segment hops, the remote_access_gateway role and the narrowed
it_ot_bypass exemption (product-neutral remote access: VPN concentrator,
Teleport-style proxy, RDP/SSH gateway -> DMZ jump host -> OT)."""
import pytest

from app.models import AccessPathHop, ApprovedHost, Baseline, Host
from app.parsers import remote_access as ra
from app.parsers.access_paths import enumerate_access_paths
from app.parsers.site_scope import analysis_site
from tests.test_access_paths import _ingest, _site, db  # noqa: F401
from tests.test_access_paths_overlay import _host
from tests.test_access_path_tags import api  # noqa: F401

IT, GW, JUMP, HMI = "10.4.0.10", "10.35.0.10", "10.35.0.20", "10.2.0.50"

CFG = f"""
config system interface
    edit "p_it"
        set vdom "root"
        set ip 10.4.0.1 255.255.255.0
    next
    edit "p_dmz"
        set vdom "root"
        set ip 10.35.0.1 255.255.255.0
    next
    edit "p_ot"
        set vdom "root"
        set ip 10.2.0.1 255.255.255.0
    next
end
config firewall address
    edit "it"
        set subnet {IT} 255.255.255.255
    next
    edit "gw"
        set subnet {GW} 255.255.255.255
    next
    edit "jump"
        set subnet {JUMP} 255.255.255.255
    next
    edit "hmi"
        set subnet {HMI} 255.255.255.255
    next
end
config firewall policy
    edit 1
        set name "it-to-gateway"
        set srcintf "p_it"
        set dstintf "p_dmz"
        set srcaddr "it"
        set dstaddr "gw"
        set action accept
        set schedule "always"
        set service "HTTPS"
    next
    edit 2
        set name "jump-to-hmi"
        set srcintf "p_dmz"
        set dstintf "p_ot"
        set srcaddr "jump"
        set dstaddr "hmi"
        set action accept
        set schedule "always"
        set service "RDP"
    next
end
"""
LEVELS = {"p_it": 4, "p_dmz": 3.5, "p_ot": 2}


def _scene(db):
    sid = _site(db, "Hop plant")
    _ingest(db, CFG, "FW", sid, LEVELS)
    _host(db, sid, GW, 3.5)
    _host(db, sid, JUMP, 3.5)
    db.commit()
    return sid


def _composed(db, sid):
    return [p for p in enumerate_access_paths(db, sid)["paths"] if p["direction"] == "composed"]


# ------------------------------------------------------------ composition --
def test_no_composed_row_until_the_hop_is_declared(db):
    sid = _scene(db)
    assert _composed(db, sid) == []              # gateway != jumpbox: nothing joins them
    with analysis_site(db, sid):
        ra.create_hop(db, sid, from_ip=GW, to_ip=JUMP, service="tcp/22, tcp/3389", note="sanctioned")
    db.commit()
    rows = _composed(db, sid)
    assert len(rows) == 1
    row = rows[0]
    assert "declared_hop" in row["flags"] and "conduit_through_dmz" in row["flags"]
    assert "it_ot_bypass" not in row["flags"]
    assert row["hop"]["from_ip"] == GW and row["hop"]["to_ip"] == JUMP
    assert row["hop"]["service"] == "tcp/22,tcp/3389"
    assert row["pivot"] == {"ip": GW, "level": 3.5}
    assert row["src"]["level"] == 4 and row["dst"]["level"] == 2
    assert [c["policy_id"] for c in row["chain"]] == ["1", "2"]
    key = row["tag_key"]
    assert key.startswith("c:")
    # deleting the hop removes the row again; the tag key is stable meanwhile
    with analysis_site(db, sid):
        hid = db.query(AccessPathHop).one().id
        ra.delete_hop(db, hid)
    db.commit()
    assert _composed(db, sid) == []
    with analysis_site(db, sid):
        ra.create_hop(db, sid, from_ip=GW, to_ip=JUMP)
    db.commit()
    assert _composed(db, sid)[0]["tag_key"] == key


def test_hop_is_directional_and_site_scoped(db):
    sid = _scene(db)
    with analysis_site(db, sid):
        ra.create_hop(db, sid, from_ip=JUMP, to_ip=GW)     # wrong way round
    db.commit()
    assert _composed(db, sid) == []
    other = _site(db, "Other plant")
    _ingest(db, CFG, "FW2", other, LEVELS)
    _host(db, other, GW, 3.5)
    _host(db, other, JUMP, 3.5)
    db.commit()
    with analysis_site(db, other):
        ra.create_hop(db, other, from_ip=GW, to_ip=JUMP)
    db.commit()
    assert len(_composed(db, other)) == 1
    assert _composed(db, sid) == []                         # another site's hop never joins ours


# ------------------------------------------------------------- validation --
def test_hop_validation(db):
    sid = _scene(db)
    _host(db, sid, "10.4.0.99", 4)
    db.commit()
    with analysis_site(db, sid):
        for kw, msg in [
            (dict(from_ip="nope", to_ip=JUMP), "not an IP"),
            (dict(from_ip=GW, to_ip=GW), "must differ"),
            (dict(from_ip=GW, to_ip="10.35.0.99"), "unknown host"),
            (dict(from_ip=GW, to_ip="10.4.0.99"), "different Purdue levels"),
            (dict(from_ip=GW, to_ip=JUMP, service="tcp/99999"), "ports must be"),
            (dict(from_ip=GW, to_ip=JUMP, service="ssh"), "service token"),
        ]:
            with pytest.raises(ra.HopError, match=msg):
                ra.create_hop(db, sid, **kw)
        ra.create_hop(db, sid, from_ip=GW, to_ip=JUMP)
        with pytest.raises(ra.HopError) as dup:
            ra.create_hop(db, sid, from_ip=GW, to_ip=JUMP)
        assert dup.value.status == 409
        with pytest.raises(ra.HopError) as nf:
            ra.delete_hop(db, 9999)
        assert nf.value.status == 404
    assert ra.normalize_service("any") is None and ra.normalize_service("") is None
    assert ra.normalize_service(["TCP/22", "tcp/22", "udp/500-501"]) == "tcp/22,udp/500-501"


# ------------------------------------------------------------ suggestions --
def test_suggestions_need_labels_and_skip_declared(db):
    sid = _scene(db)
    with analysis_site(db, sid):
        assert ra.suggest_hops(db) == []                     # nothing labelled yet
        db.query(Host).filter(Host.ip == GW).one().role = "remote_access_gateway"
        db.query(Host).filter(Host.ip == JUMP).one().device_type = "jump_host"
        db.flush()
        sug = ra.suggest_hops(db)
        assert [(s["from_ip"], s["to_ip"], s["level"]) for s in sug] == [(GW, JUMP, 3.5)]
        ra.create_hop(db, sid, from_ip=GW, to_ip=JUMP)
        assert ra.suggest_hops(db) == []                     # already declared


def test_suggestions_skip_other_levels(db):
    sid = _scene(db)
    with analysis_site(db, sid):
        db.query(Host).filter(Host.ip == GW).one().role = "remote_access_gateway"
        j = db.query(Host).filter(Host.ip == JUMP).one()
        j.device_type, j.purdue_level = "jump_host", 3
        db.flush()
        assert ra.suggest_hops(db) == []


# -------------------------------------------------- narrowed bypass flag --
def test_direct_chain_through_dmz_is_bypass(db):
    """L4 -> L1 routed straight through a DMZ firewall pair keeps the same
    source and destination end to end: the DMZ terminates nothing, so it is a
    bypass (the exemption is only for composed rows)."""
    from app.parsers.topology_manager import set_upstream_firewall
    from tests.test_access_paths import _policy, _two_leg_cfg
    sid = _site(db, "Chain plant")
    cfg1 = _two_leg_cfg("p_dmz", "p_it", "10.35.0.1", "10.4.0.1", _policy(100, "it-dmz", "p_it", "p_dmz", "ALL"))
    cfg2 = _two_leg_cfg("p_l1", "p_dmz", "10.1.0.1", "10.35.0.2", _policy(200, "dmz-l1", "p_dmz", "p_l1", "ALL"))
    fw1 = _ingest(db, cfg1, "FW1", sid, {"p_it": 4, "p_dmz": 3.5})
    fw2 = _ingest(db, cfg2, "FW2", sid, {"p_dmz": 3.5, "p_l1": 1})
    set_upstream_firewall(db, fw2.id, fw1.id, site_id=sid)
    db.commit()
    paths = enumerate_access_paths(db, sid)["paths"]
    rows = [p for p in paths if p["direction"] == "down"
            and p["src"]["level"] == 4 and p["dst"]["level"] == 1]
    assert rows and all("it_ot_bypass" in p["flags"] for p in rows)
    assert all("it_ot_bypass" not in p["flags"] for p in paths if p["direction"] == "composed")


# ------------------------------------------------------------------- API --
def test_endpoints_create_list_delete_and_compose(api):
    s = api.Session()
    sid = _scene(s)
    s.close()
    r = api.post("/access-paths/hops", json={"site_id": sid, "from_ip": GW, "to_ip": JUMP,
                                             "service": "tcp/22,tcp/3389", "created_by": "ops"})
    assert r.status_code == 201, r.text
    hid = r.json()["id"]
    assert api.post("/access-paths/hops", json={"site_id": sid, "from_ip": GW, "to_ip": JUMP}).status_code == 409
    assert api.post("/access-paths/hops", json={"site_id": sid, "from_ip": GW, "to_ip": "x"}).status_code == 422
    got = api.get("/access-paths/hops", params={"site_id": sid}).json()
    assert [h["id"] for h in got["hops"]] == [hid] and got["suggestions"] == []
    paths = api.get("/access-paths", params={"site_id": sid}).json()["paths"]
    comp = [p for p in paths if p["direction"] == "composed"]
    assert len(comp) == 1 and comp[0]["hop"]["to_ip"] == JUMP
    # the composed row is classifiable like any other
    c = api.post("/access-paths/classify", json={"site_id": sid, "items": [
        {"tag_key": comp[0]["tag_key"], "classification": "reviewed_ok", "note": "MFA at gateway"}]})
    assert c.status_code == 200
    assert api.delete(f"/access-paths/hops/{hid}", params={"site_id": sid}).status_code == 200
    assert api.delete(f"/access-paths/hops/{hid}", params={"site_id": sid}).status_code == 404
    after = api.get("/access-paths", params={"site_id": sid}).json()
    assert not [p for p in after["paths"] if p["direction"] == "composed"]
    assert len(after["orphaned_tags"]) == 1                   # the tag outlives the hop


def test_hop_is_not_visible_from_another_site(api):
    s = api.Session()
    a, b = _scene(s), None
    b = _site(s, "Second")
    _ingest(s, CFG, "FW-B", b, LEVELS)
    _host(s, b, GW, 3.5)
    _host(s, b, JUMP, 3.5)
    s.commit()
    s.close()
    hid = api.post("/access-paths/hops", json={"site_id": a, "from_ip": GW, "to_ip": JUMP}).json()["id"]
    assert api.get("/access-paths/hops", params={"site_id": b}).json()["hops"] == []
    assert api.delete(f"/access-paths/hops/{hid}", params={"site_id": b}).status_code == 404


def test_baseline_csv_accepts_gateway_role(db):
    from app.parsers.baseline_parser import ingest_approved_hosts
    sid = _site(db, "Csv plant")
    csv = "ip,role,hostname\n10.35.0.6,remote_access_gateway,vpn\n10.35.0.5,jump_host,jb\n10.1.0.1,bogus,x\n"
    stats = ingest_approved_hosts(csv, db, "b", site_id=sid)
    assert stats["hosts_loaded"] == 2 and stats["skipped_bad_role"] == 1
    db.commit()
    with analysis_site(db, sid):
        assert ra.gateway_ips(db) == {"10.35.0.6"} and ra.jump_host_ips(db) == {"10.35.0.5"}


# ------------------------------------------------------ audit E (2026-10-05) --
def test_hop_accepts_non_canonical_addresses(db):
    """E-01: Host.ip is stored as ingested; the hop still finds it."""
    sid = _scene(db)
    _host(db, sid, "2001:DB8:0:0:0:0:0:10", 3.5)
    _host(db, sid, "2001:db8::0:20", 3.5)
    db.commit()
    with analysis_site(db, sid):
        h = ra.create_hop(db, sid, from_ip=" 2001:db8::10 ", to_ip="2001:DB8::20")
        assert (h.from_ip, h.to_ip) == ("2001:db8::10", "2001:db8::20")
        assert "AccessPathHop" in repr(h) and "2001:db8::10->2001:db8::20" in repr(h)   # E-03
        h2 = ra.create_hop(db, sid, from_ip="010.35.0.10".replace("010", "10"), to_ip=JUMP)
        assert h2.from_ip == GW


def test_service_edge_cases(db):
    assert ra.normalize_service("any, tcp/22") is None                   # E-10: any swallows the rest
    assert ra.normalize_service(["TCP/22", " tcp/22 ", "udp/500-600"]) == "tcp/22,udp/500-600"
    with pytest.raises(ra.HopError) as e:                                # E-04: String(255) column
        ra.normalize_service(",".join(f"udp/{10000 + i}-{20000 + i}" for i in range(20)))
    assert "255" in str(e.value)


def test_duplicate_race_is_409(db, monkeypatch):
    """E-06: two declarations racing past the pre-check end in the unique
    index, which must surface as 409, not 500."""
    sid = _scene(db)
    with analysis_site(db, sid):
        ra.create_hop(db, sid, from_ip=GW, to_ip=JUMP)
        db.flush()
        real = db.query

        def blind(*a, **k):      # the pre-check sees nothing, as the loser of a race would
            q = real(*a, **k)
            if a and a[0] is AccessPathHop:
                return q.filter(AccessPathHop.id < 0)
            return q
        monkeypatch.setattr(db, "query", blind)
        with pytest.raises(ra.HopError) as e:
            ra.create_hop(db, sid, from_ip=GW, to_ip=JUMP)
        assert e.value.status == 409
    db.rollback()


def test_suggestions_skip_baseline_only_addresses_and_tolerate_role_spelling(db):
    """E-05 / E-09: a baseline address with no host row cannot be declared,
    so it is not suggested; role spelling differences do not hide a label."""
    sid = _scene(db)
    with analysis_site(db, sid):
        b = Baseline(name="B", is_active=True, site_id=sid)
        db.add(b)
        db.flush()
        db.add(ApprovedHost(baseline_id=b.id, ip="10.35.0.99", role="remote_access_gateway"))
        db.query(Host).filter(Host.ip == GW).one().role = "Remote-Access-Gateway"
        db.query(Host).filter(Host.ip == JUMP).one().device_type = "jump_host"
        db.flush()
        assert ra.gateway_ips(db) == {"10.35.0.99", GW}
        assert [(s["from_ip"], s["to_ip"]) for s in ra.suggest_hops(db)] == [(GW, JUMP)]


def test_list_hops_flags_stale_hops(db):
    """E-08: a hop whose hosts vanished or drifted to another level says so."""
    sid = _scene(db)
    with analysis_site(db, sid):
        ra.create_hop(db, sid, from_ip=GW, to_ip=JUMP)
        db.flush()
        [row] = ra.list_hops(db)
        assert (row["from_known"], row["to_known"], row["level_mismatch"]) == (True, True, False)
        db.query(Host).filter(Host.ip == JUMP).one().purdue_level = 3
        db.flush()
        assert ra.list_hops(db)[0]["level_mismatch"] is True
        db.query(Host).filter(Host.ip == GW).delete()
        db.flush()
        [row] = ra.list_hops(db)
        assert row["from_known"] is False and row["level_mismatch"] is False


# --------------------------------------------------------------- D-11 --
def test_rows_without_level_evidence_are_flagged_direction_unverified(db):
    """D-11: a boundary firewall whose interfaces carry no Purdue level has its
    rules applied in both directions by default; the rows say so, and the
    envelope names the firewall and its unlabelled interfaces.  Labelling the
    interfaces removes the flag (and the reversed rows)."""
    from app.models import Firewall
    sid = _site(db, "Unlabelled plant")
    fw = _ingest(db, CFG, "FW", sid, {})                 # no interface levels
    fw.purdue_level_ingress, fw.purdue_level_egress = 4, 2
    db.commit()
    res = enumerate_access_paths(db, sid)
    assert res["paths"], "the ingress/egress boundary still yields rows"
    assert all("direction_unverified" in p["flags"] for p in res["paths"])
    assert res["counts"]["by_flag"]["direction_unverified"] == len(res["paths"])
    [note] = res["unlabelled_firewalls"]
    assert note["firewall_id"] == fw.id and note["firewall"] == "FW"
    assert set(note["unlabelled_interfaces"]) == {"p_it", "p_dmz", "p_ot"}
    # label the interfaces: evidence restores the real direction, flag gone
    from app.models import FirewallInterface
    for fi in db.query(FirewallInterface).filter(FirewallInterface.firewall_id == fw.id):
        fi.purdue_level = LEVELS[fi.name]
    db.commit()
    res = enumerate_access_paths(db, sid)
    assert res["paths"] and res["unlabelled_firewalls"] == []
    assert not any("direction_unverified" in p["flags"] for p in res["paths"])
    assert all(p["direction"] == "down" for p in res["paths"])

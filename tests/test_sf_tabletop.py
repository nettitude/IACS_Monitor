"""Segmented-firewall tabletop (SF) fixes: VNC / WinRM count as management
ports (SF-3), a level-skipping session opened by the OT side is worded as the
OT host reaching up (SF-2), and the unknown-level hold on auto-resolve keeps
only findings about the host whose level is unknown (SF-10)."""
import pytest

from app.models import Finding
from app.parsers import alert_engine as ae
from app.parsers.alert_engine import _bypass_wording, run_periodic_reviews
from tests.test_findings_lifecycle import _sess, db  # noqa: F401  (fixture)


def _findings(db, check):
    return db.query(Finding).filter(Finding.check_name == check, Finding.status == "open").all()


def test_vnc_is_a_management_port(db):
    _sess(db, "10.50.2.30", "10.50.1.21", 5900, src_level=3, dst_level=2)
    _sess(db, "10.50.2.31", "10.50.1.21", 5985, src_level=3, dst_level=2)
    db.commit()
    ae.review_ns_mgmt_from_non_admin(db)
    db.commit()
    titles = {f.title for f in _findings(db, "session_mgmt_from_non_admin")}
    assert any(":5900" in t for t in titles) and any(":5985" in t for t in titles)


def test_bypass_wording_names_the_initiator():
    down = _bypass_wording(4, 2)
    up = _bypass_wording(4, 2, ot_initiated=True)
    assert down["title"] == "Direct IT-to-OT session"
    assert up["title"] == "Control-zone host straight to IT"
    assert up["skips"].endswith("(supervisory control straight up to enterprise)")
    assert _bypass_wording(3, 1, ot_initiated=True)["title"] == "Level-skipping session (OT host reaching up)"
    assert _bypass_wording(3.5, 1, ot_initiated=True)["title"] == "Controller straight to the DMZ"


def test_session_bypass_title_follows_the_client(db):
    # an HMI (L2) opening LDAP to the enterprise AD server (L4): the HMI is the client
    _sess(db, "10.50.1.21", "10.50.3.5", 389, src_level=2, dst_level=4)
    db.commit()
    ae.review_ns_it_ot_bypass(db)
    db.commit()
    (f,) = _findings(db, "session_it_ot_bypass")
    assert f.title.startswith("Control-zone host straight to IT (observed traffic): 10.50.1.21 (L2) → 10.50.3.5 (L4) port 389")
    assert f.detail["direction"] == "ot_to_it" and f.detail["initiator"] == "10.50.1.21"
    assert f.severity == "high"


def test_unknown_level_hold_is_per_unknown_host(db):
    """A bypass finding between two known hosts closes when it is no longer
    detected, even though one of them also talked to a host of unknown level."""
    vpn = _sess(db, "10.50.200.5", "10.50.4.10", 3389, src_level=5, dst_level=2)   # jump box misclassified L2
    _sess(db, "10.100.5.50", "10.50.4.10", 3389, src_level=None, dst_level=2)      # corporate admin: no level
    db.commit()
    run_periodic_reviews(db)
    db.commit()
    assert len(_findings(db, "session_it_ot_bypass")) == 1
    # the operator classifies the jump box: no longer a bypass
    vpn.dst_host.purdue_level = 3.5
    vpn.dst_host.device_type = "jump_host"
    db.commit()
    run_periodic_reviews(db)
    db.commit()
    assert _findings(db, "session_it_ot_bypass") == []


# ------------------------------------------------ owner decisions (SF round 2) --

def _mctx(db):
    from app.parsers.mgmt_networks import build_context
    return build_context(db)


def test_host_may_hold_several_roles(db):
    from app.parsers import mgmt_networks as mg
    from app.models import Site
    site = Site(name="S", code="s")
    db.add(site)
    db.flush()
    r1, c1 = mg.declare(db, site.id, kind="host", cidr="10.50.4.10", role="jump_host")
    r2, c2 = mg.declare(db, site.id, kind="host", cidr="10.50.4.10", role="engineering_ws")
    assert c1 and c2 and r1.id != r2.id
    with pytest.raises(mg.MgmtError):
        mg.declare(db, site.id, kind="host", cidr="10.50.4.10", role="jump_host")   # 409: same role twice
    db.commit()
    ctx = _mctx(db)
    assert ctx.is_jump_host("10.50.4.10") and ctx.is_engineering_ip("10.50.4.10") and ctx.is_admin_ip("10.50.4.10")


def test_declared_ntp_server_is_exempt(db):
    from app.parsers import mgmt_networks as mg
    from app.models import Site
    site = Site(name="S", code="s")
    db.add(site)
    db.flush()
    mg.declare(db, site.id, kind="host", cidr="10.50.2.5", role="ntp_server")
    db.commit()
    ctx = _mctx(db)
    assert ctx.is_ntp_server("10.50.2.5") and not ctx.is_admin_ip("10.50.2.5", ot=True)
    assert ctx.is_ntp_flow("10.50.1.11", 123, "10.50.2.5", 123)
    assert not ctx.is_ntp_flow("10.50.1.11", 123, "162.159.200.1", 123)
    assert ctx.is_ntp_scope("10.50.2.5/32", ["tcp/123", "udp/123"])
    assert not ctx.is_ntp_scope("10.50.2.0/24", ["udp/123"]) and not ctx.is_ntp_scope("10.50.2.5", ["udp/53"])
    # a PLC syncing time with it: neither a level skip nor an IT dependency
    _sess(db, "10.50.1.11", "10.50.2.5", 123, transport="udp", src_level=1, dst_level=3)
    _sess(db, "10.50.1.12", "162.159.200.1", 123, transport="udp", src_level=1, dst_level=5)
    db.commit()
    ae.review_ns_it_ot_bypass(db)
    ae.review_ot_it_dependencies(db)
    db.commit()
    titles = [f.title for f in db.query(Finding).filter(Finding.status == "open")]
    assert not any("10.50.2.5" in t for t in titles), titles
    assert any("162.159.200.1" in t or "10.50.1.12" in t for t in titles)


def test_fix_option_offers_the_ntp_server(db):
    from app.parsers.mgmt_networks import fix_options
    _sess(db, "10.50.1.11", "10.50.2.5", 123, transport="udp", src_level=1, dst_level=3)
    db.commit()
    ae.review_ns_it_ot_bypass(db)
    db.commit()
    (f,) = _findings(db, "session_it_ot_bypass")
    opts = fix_options(db, f)["options"]
    assert opts and opts[0]["role"] == "ntp_server" and opts[0]["cidr"] == "10.50.2.5"


def test_false_positive_is_never_raised_again(db):
    from datetime import datetime, timezone
    _sess(db, "10.50.4.10", "10.50.1.11", 102, src_level=3.5, dst_level=1)
    db.commit()
    ae.review_ns_it_ot_bypass(db)
    db.commit()
    (f,) = _findings(db, "session_it_ot_bypass")
    f.status = "false_positive"
    f.false_positive_reason = "jump box engineering conduit"
    f.false_positive_by = "p.m"
    f.false_positive_at = datetime.now(timezone.utc)
    db.commit()
    run_periodic_reviews(db)
    db.commit()
    rows = db.query(Finding).filter(Finding.check_name == "session_it_ot_bypass").all()
    assert len(rows) == 1 and rows[0].status == "false_positive"
    assert rows[0].occurrence_count >= 2                       # re-detected silently
    assert rows[0].false_positive_reason == "jump box engineering conduit"

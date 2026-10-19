"""
Admin access on a disabled interface (owner, 2026-10-12, option 2): the finding stays,
lowered to low with "(interface disabled)" and a severity reason - its allowaccess goes
live the moment the port is enabled.  Applies to config_mgmt_not_restricted_to_mgmt_zone
(mgmt_networks, from the stored interfaces) and config_insecure_mgmt_protocol (config upload).
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, configure_sqlite_engine
from app.models import CHECK_TYPE_REFERENCE, Finding
from app.parsers.forti_config_parser import ingest_fortigate_config

CFG = """config system interface
    edit "port1"
        set ip 10.30.1.1 255.255.255.0
        set allowaccess https ssh
    next
    edit "port3"
        set ip 10.30.3.1 255.255.255.0
        set allowaccess https ssh telnet
{STATUS}    next
end
"""


def _findings(db, status):
    ingest_fortigate_config(CFG.replace("{STATUS}", status), db, firewall_name="FW-D", generate_findings=True)
    db.commit()
    return {(f.check_name, f.detail.get("interface")): f for f in db.query(Finding).filter(Finding.status == "open")}


def test_disabled_interface_findings_are_low_and_kept():
    engine = create_engine("sqlite:///:memory:")
    configure_sqlite_engine(engine)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    f = _findings(db, "        set status down\n")
    zone = f[("config_mgmt_not_restricted_to_mgmt_zone", "port3")]
    ins = f[("config_insecure_mgmt_protocol", "port3")]
    for x in (zone, ins):
        assert x.severity == "low" and x.title.endswith("(interface disabled)")
        assert x.detail["interface_disabled"] is True and "administratively down" in x.detail["severity_reason"]
    # the enabled port keeps the catalogue severity
    up = f[("config_mgmt_not_restricted_to_mgmt_zone", "port1")]
    assert up.severity == CHECK_TYPE_REFERENCE["config_mgmt_not_restricted_to_mgmt_zone"][2]
    assert up.detail["interface_disabled"] is False
    # the port is enabled in the next config: the same findings go back to their full severity
    f2 = _findings(db, "")
    assert f2[("config_mgmt_not_restricted_to_mgmt_zone", "port3")].id == zone.id
    assert f2[("config_mgmt_not_restricted_to_mgmt_zone", "port3")].severity == \
        CHECK_TYPE_REFERENCE["config_mgmt_not_restricted_to_mgmt_zone"][2]
    assert f2[("config_insecure_mgmt_protocol", "port3")].severity == "high"
    assert not f2[("config_insecure_mgmt_protocol", "port3")].title.endswith("(interface disabled)")

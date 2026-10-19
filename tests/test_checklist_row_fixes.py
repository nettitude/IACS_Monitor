"""
Checklist rows corrected against the owner's workbook (2026-10-12, "make the recommended
change"): workbook 3.10 = rule documentation, 3.11 = temporary rules, so
  config_ids_ips_missing            3.10 -> 3.12 (inspection / industrial DPI)
  config_av_missing_on_file_policy  3.11 -> no row (SR 3.2 / 3.3 only)
  fqdn_in_policy                    3.10 -> no row (SR 7.6 only)
The PDF groups no-row checks under "Not in the checklist (62443-3-3 SR only)".
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import generate_report as gr
from app.db import Base, configure_sqlite_engine
from app.models import CHECK_TYPE_REFERENCE, Finding
from app.parsers.forti_config_parser import ingest_fortigate_config

CFG = """config system interface
    edit "port1"
        set ip 10.1.1.1 255.255.255.0
    next
    edit "port2"
        set ip 10.1.2.1 255.255.255.0
    next
end
config firewall address
    edit "vendor"
        set type fqdn
        set fqdn "updates.vendor.example"
    next
end
config firewall policy
    edit 7
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "vendor"
        set service "HTTP" "FTP"
        set action accept
        set logtraffic all
    next
end
"""


def test_catalogue_rows():
    assert CHECK_TYPE_REFERENCE["config_ids_ips_missing"][1] == "3.12"
    assert CHECK_TYPE_REFERENCE["config_av_missing_on_file_policy"][1] == ""
    assert CHECK_TYPE_REFERENCE["fqdn_in_policy"][1] == ""
    assert gr.section_of("") == "?" and gr.SECTION_NAMES["?"] == "Other"     # owner 2026-10-17: no SR in the headings


def test_emitted_findings_carry_the_new_rows():
    engine = create_engine("sqlite:///:memory:")
    configure_sqlite_engine(engine)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    ingest_fortigate_config(CFG, db, firewall_name="FW", generate_findings=True)
    db.commit()
    rows = {f.check_name: f.checklist_id for f in db.query(Finding)}
    assert rows.get("config_ids_ips_missing") == "3.12"
    assert rows.get("config_av_missing_on_file_policy") == ""
    assert rows.get("fqdn_in_policy") == ""

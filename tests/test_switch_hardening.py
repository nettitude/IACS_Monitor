"""G-03: switch SNMP community / telnet hardening findings."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import CHECK_TYPE_REFERENCE, Finding
from app.parsers import switch_hardening as sh
from app.parsers.switch_parser import ingest_switch_config


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


HP = """; J9772A Configuration Editor
hostname "HP-SW-L1"
telnet-server
ip ssh
snmp-server community "public" Unrestricted
snmp-server community "plantro" Operator
vlan 50
   name "BASIC_CONTROL"
   untagged 1-5
   exit
"""

CISCO = """hostname CORE-SW-01
snmp-server community private RW 10
snmp-server community n0t-d3fault RO
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
!
line vty 0 4
 transport input telnet ssh
!
"""


def _open(db, check):
    return db.query(Finding).filter(Finding.check_name == check, Finding.status == "open").all()


def test_hp_public_community_and_telnet(db):
    st = ingest_switch_config(HP, db, vendor_hint="hp")
    assert st["hardening"]["default_communities"] == 1 and st["hardening"]["telnet"] is True
    [d] = _open(db, "switch_snmp_default_community")
    assert d.severity == "critical"                       # Unrestricted = write access
    assert d.device_name == "HP-SW-L1" and '"public"' in d.title
    assert d.isa62443_sr == CHECK_TYPE_REFERENCE["switch_snmp_default_community"][0] == "SR 1.5, SR 4.1"
    assert d.detail["access"] == "read-write"
    [c] = _open(db, "switch_snmp_cleartext_community")
    assert c.severity == "low" and "plantro" not in c.title and c.detail["community_masked"] == "p*****o"
    [t] = _open(db, "switch_insecure_mgmt_protocol")
    assert t.severity == "high"


def test_reingest_is_idempotent_and_fix_closes(db):
    ingest_switch_config(HP, db, vendor_hint="hp")
    ingest_switch_config(HP, db, vendor_hint="hp")
    assert len(_open(db, "switch_snmp_default_community")) == 1
    fixed = HP.replace('snmp-server community "public" Unrestricted\n', "").replace(
        "telnet-server\n", "no telnet-server\n")
    st = ingest_switch_config(fixed, db, vendor_hint="hp")
    assert st["hardening"]["findings_closed"] == 2
    assert _open(db, "switch_snmp_default_community") == []
    assert _open(db, "switch_insecure_mgmt_protocol") == []
    assert len(_open(db, "switch_snmp_cleartext_community")) == 1


def test_cisco_communities_and_vty_telnet(db):
    st = ingest_switch_config(CISCO, db, vendor_hint="cisco")
    assert st["hardening"]["communities"] == 2
    [d] = _open(db, "switch_snmp_default_community")
    assert d.severity == "critical" and "private" in d.title     # RW
    [c] = _open(db, "switch_snmp_cleartext_community")
    assert c.severity == "low"
    [t] = _open(db, "switch_insecure_mgmt_protocol")
    assert "transport input telnet" in t.detail["config_line"]


def test_parsers_only_judge_what_is_stated():
    assert sh.telnet_enabled("hostname X\nno telnet-server\n", "hp") is None
    assert sh.telnet_enabled("hostname X\n", "hp") is None                # default not assumed
    assert sh.telnet_enabled("line vty 0 4\n transport input ssh\n", "cisco") is None
    assert sh.telnet_enabled("line vty 0 4\n transport input all\n", "cisco")
    assert sh.parse_communities('snmp-server community "Public" operator', "hp")[0]["write"] is False

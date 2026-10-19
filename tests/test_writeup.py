"""
Per-check write-up (owner 2026-10-17): concern, why, remediation, standard /
best-practice references, FortiOS example filled from the finding, closes.
"""
from app import writeup as wu
from app.models import CHECK_TYPE_REFERENCE as REF
from app.parsers.forti_config_parser import FORTIGATE_CONFIG_CHECKS


def test_every_check_has_references_and_a_concern():
    for name, (sr, _row, _sev, _cat) in REF.items():
        w = wu.writeup(name, sr)
        assert w["references"], name
        assert any(r.startswith("IEC 62443") for r in w["references"]), name
        assert w["concern"] and w["why"] and w["fix"] and w["closes"], name


def test_references_name_the_sr_title_nist_and_cis():
    refs = wu.references("config_admin_no_trusted_hosts", "SR 5.1, SR 2.1")
    assert refs[0] == "IEC 62443-3-3 SR 5.1 (Network segmentation)"
    assert refs[1] == "IEC 62443-3-3 SR 2.1 (Authorization enforcement)"
    assert any(r.startswith("NIST SP 800-82r3") and "SC-7" in r for r in refs)
    assert refs[-1].startswith("CIS Fortinet FortiGate Benchmark")
    assert "IEC 62443-3-3 SR 5.1 RE 2 (Network segmentation)" in wu.references("rule_dns_external", "SR 5.1 RE2, SR 7.6")
    assert wu.references("config_temporary_rule", "2-1 SPE 2")[0].startswith("IEC 62443-2-1 SPE 2")
    assert any(r == "IEC 62443 (zone and conduit design)" for r in wu.references("zone_doc_1_1", "SR 5.1"))


def test_every_fortigate_config_check_has_a_fortios_example():
    missing = [n for n in FORTIGATE_CONFIG_CHECKS if n not in wu.FORTI]
    assert missing == []
    for n in FORTIGATE_CONFIG_CHECKS:
        assert "config " in wu.FORTI[n] and "end" in wu.FORTI[n], n


def test_fortios_example_is_filled_from_the_finding():
    ex = wu.forti_example("rule_dns_external", {"policy_id": 306, "policy_name": "DNS_Services",
                                                 "src_zone": "vlan_20,vlan_22", "dst_zone": "wan1", "dst": "8.8.8.8"})
    assert "edit 306" in ex and '"DNS_Services"' in ex and 'set srcintf "vlan_20" "vlan_22"' in ex and "was wan1" in ex and "was 8.8.8.8" in ex
    ex = wu.forti_example("config_admin_no_trusted_hosts", {"username": "ot-ops"})
    assert 'edit "ot-ops"' in ex and "<management network>" in ex
    generic = wu.forti_example("config_admin_no_trusted_hosts", None)
    assert 'edit "<admin account>"' in generic
    assert wu.forti_example("unknown_device", {"ip": "10.1.1.1"}) is None


def test_concern_defaults_to_the_first_sentence_of_why():
    assert wu.concern("config_implicit_deny_not_logged", "x") == wu.CONCERN["config_implicit_deny_not_logged"]
    assert wu.concern("some_check", "First sentence here. Second one.") == "First sentence here."


def test_multi_interface_values_quoted_only_where_the_template_quotes_them():
    ex = wu.forti_example("rule_it_ot_bypass", {"policy_id": 7, "policy_name": "x", "src_zone": "vlan_20,vlan_22", "dst_zone": "port1", "service": "tcp/22"})
    assert '# "x": vlan_20, vlan_22 -> port1' in ex                      # comment: plain list
    ex = wu.forti_example("rule_dns_external", {"policy_id": 31, "src_zone": "vlan_20,vlan_22", "dst_zone": "wan1"})
    assert 'set srcintf "vlan_20" "vlan_22"' in ex and "was wan1" in ex    # setting: quoted tokens

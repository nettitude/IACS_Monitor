"""Access Review roll-up (owner request 2026-10-11): rows that differ only in
the destination host (or only in the source host) are one line in the review
screen and the PDF, while the enumeration, tags and counts stay per row.

The site mirrors the owner's case: a dial-up VPN user reaches a DMZ jump host
(policy 201), and one policy (102) lets the jump host SSH to an address group
of controllers across three VLANs - N composed rows for one logical conduit."""
import io
import re

from pypdf import PdfReader

import generate_report as gr
from app.parsers import access_path_groups as apg
from app.parsers.access_paths import classify_access_paths, enumerate_access_paths
from tests.test_access_paths import _ingest, _site, db  # noqa: F401  (db fixture)

CTRL = ["10.168.20.20", "10.168.21.101", "10.168.21.102", "10.168.21.103", "10.168.22.20"]

CFG = """
config system interface
    edit "wan1"
        set vdom "root"
        set ip 203.0.113.2 255.255.255.252
    next
    edit "dmz"
        set vdom "root"
        set ip 10.168.32.1 255.255.255.0
    next
    edit "vlan_20"
        set vdom "root"
        set ip 10.168.20.1 255.255.255.0
    next
    edit "vlan_21"
        set vdom "root"
        set ip 10.168.21.1 255.255.255.0
    next
    edit "vlan_22"
        set vdom "root"
        set ip 10.168.22.1 255.255.255.0
    next
end
config firewall address
    edit "vpn_user"
        set subnet 192.168.201.1 255.255.255.255
    next
    edit "jump"
        set subnet 10.168.32.10 255.255.255.255
    next
""" + "".join(f"""    edit "ctrl-{ip}"
        set subnet {ip} 255.255.255.255
    next
""" for ip in CTRL) + """end
config firewall addrgrp
    edit "Controllers"
        set member """ + " ".join(f'"ctrl-{ip}"' for ip in CTRL) + """
    next
end
config firewall policy
    edit 201
        set name "Trinasolar_VPN_LPS"
        set srcintf "wan1"
        set dstintf "dmz"
        set srcaddr "vpn_user"
        set dstaddr "jump"
        set action accept
        set schedule "always"
        set service "SSH"
    next
    edit 102
        set name "Controllers-LPS_To_Switches"
        set srcintf "dmz"
        set dstintf "vlan_20" "vlan_21" "vlan_22"
        set srcaddr "jump"
        set dstaddr "Controllers"
        set action accept
        set schedule "always"
        set service "SSH"
    next
end
"""
LEVELS = {"wan1": 5, "dmz": 3.5, "vlan_20": 2, "vlan_21": 2, "vlan_22": 2}


def _plant(db):
    sid = _site(db, "LPS")
    _ingest(db, CFG, "site-a-rout01", sid, LEVELS)
    return sid


def test_group_keys_and_roll_up(db):
    sid = _plant(db)
    paths = enumerate_access_paths(db, sid)["paths"]
    composed = [p for p in paths if p["direction"] == "composed"]
    assert len(composed) == len(CTRL)                       # one row per controller
    assert all(p["group_dst"] and p["group_src"] for p in paths)
    assert len({p["group_dst"] for p in composed}) == 1     # same source / legs / service / flags
    assert len({p["group_src"] for p in composed}) == len(CTRL)
    # leg 2 alone (jump -> each controller) rolls up too; leg 1 stays single
    lines = apg.roll_up(paths)
    groups = [g for g in lines if g["vary"]]
    assert len(groups) == 2 and all(g["vary"] == "dst" for g in groups)
    for g in groups:
        assert len(g["rows"]) == len(CTRL)
        assert sorted(g["scopes"]) == sorted(f"{ip}/32" for ip in CTRL)
    assert sum(len(g["rows"]) for g in lines) == len(paths)
    assert [g for g in lines if not g["vary"]] and len(lines) == 3
    # a different flag or service breaks the group
    other = dict(composed[0], flags=composed[0]["flags"] + ["permit_any"])
    assert apg.group_key(other, "dst") != composed[0]["group_dst"]
    other = dict(composed[0], service=["tcp/23"])
    assert apg.group_key(other, "dst") != composed[0]["group_dst"]
    # a row of another classification still shares the key: the caller splits
    assert apg.group_key(dict(composed[0], classification="exception"), "dst") == composed[0]["group_dst"]
    # unexplained flows never roll up
    assert apg.group_key({"client": {"ip": "1.1.1.1"}, "server": {"ip": "2.2.2.2"}}, "dst") == ""


def _pdf_text(db, **opts) -> str:
    pdf = gr.generate_report_bytes(db, **opts)
    reader = PdfReader(io.BytesIO(pdf))
    return re.sub(r"\s+", " ", " ".join(page.extract_text() or "" for page in reader.pages))


def test_report_prints_one_line_per_group(db):
    sid = _plant(db)
    paths = enumerate_access_paths(db, sid)["paths"]
    # include everything; classify two composed rows as an exception so the
    # roll-up never mixes classifications on one line
    composed = [p for p in paths if p["direction"] == "composed"]
    exc = {p["tag_key"] for p in composed[:2]}
    classify_access_paths(db, sid, [
        dict({"tag_key": p["tag_key"], "report_include": True},
             **({"classification": "exception", "note": "vendor SSH"} if p["tag_key"] in exc else {}))
        for p in paths])
    db.commit()
    [sec] = gr.collect_report_data(db, site_id=sid)["access_paths"]
    assert sec["included"] == len(paths)                     # counts stay per path
    printed = {g: len(v) for g, v in sec["rolled"].items()}
    assert printed["accepted"] == 1 and printed["unclassified"] == 3      # 3 composed + 5 leg-2 + leg 1 -> 1 + 1 + 1
    assert sec["printed"] == 4
    acc = sec["rolled"]["accepted"][0]
    assert acc["members"] == 2 and acc["vary"] == "dst"
    assert acc["path"].startswith("L5") and "2 destinations in L2" in acc["path"]
    assert "10.168.32.10" in acc["path"]                     # the pivot
    assert acc["hosts"] == sorted(acc["hosts"]) or len(acc["hosts"]) == 2
    assert acc["traffic"].startswith("No capture loaded") and "all 2" in acc["traffic"]
    assert acc["note"] == "vendor SSH"
    unc = [ln for ln in sec["rolled"]["unclassified"] if ln.get("members")]
    assert sorted(ln["members"] for ln in unc) == [3, 5]
    big = next(ln for ln in unc if ln["members"] == 5)
    assert "5 destinations in L2" in big["path"] and len(big["hosts"]) == 5
    text = _pdf_text(db, site_id=sid)
    assert f"This section lists the {len(paths)} lines" in text
    assert "rolled into one (4 printed)" in text
    assert "Unclassified, for review (9) · 3 lines" in text
    assert "5 destinations in L2" in text and "2 destinations in L2" in text
    assert "10.168.21.103/32" in text                        # hosts listed under the line
    assert "Total " + str(len(paths)) in text


def test_many_hosts_are_abbreviated(db):
    rows = []
    for i in range(12):
        rows.append({"tag_key": f"k{i}", "direction": "down", "service": ["tcp/22"], "protocol": ["tcp"],
                     "src": {"level": 4, "zone": "it", "scope": "10.1.0.5/32"},
                     "dst": {"level": 2, "zone": "ot", "scope": f"10.2.0.{i}/32"},
                     "chain": [{"firewall_name": "FW", "policy_id": "7"}], "flags": ["it_ot_bypass"],
                     "classification": "unclassified", "traffic": {"status": "seen", "sessions": 1}})
    apg.annotate(rows)
    [g] = apg.roll_up(rows)
    line = gr._ap_group_line(g["rows"], "path", {}, None, g["vary"], g["scopes"])
    assert line["hosts"][-1] == "+4 more" and len(line["hosts"]) == gr._AP_HOSTS_SHOWN + 1
    assert line["traffic"] == "Seen in capture on 12 of 12 (12 sessions)"
    assert line["rule_hits"] is None

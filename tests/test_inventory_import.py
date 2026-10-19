"""Asset Inventory CSV import with a column mapping (owner request 2026-10-11):
suggestions, preview checks, mapped import, saved mappings per site, and the
columns an import left out."""
import json

import pytest

from app.parsers import inventory_mapping as im
from tests.test_cov_routes import _api

VENDOR_CSV = (
    "Asset Tag,IP_Address,MAC-Address,Host Name,Asset Type,Purdue Level,Vendor,Notes\n"
    "A-1,10.20.1.11,00:1b:1b:00:00:11,PLC-01,PLC,1,Siemens,line 1\n"
    "A-2,10.20.1.21,00:1b:1b:00:00:21,HMI-01,Operator Panel,2,Siemens,\n"
    "A-3,10.20.1.31,,EWS-01,Engineering Workstation,3,Dell,\n"
    "A-4,,,GHOST,PLC,1,Siemens,no address\n"
    "A-5,10.20.1.99,,BAD-LVL,plc,banana,Siemens,\n"
)

# columns named so that nothing maps by name: only the preview's guesses /
# value sniffing find the addresses
OPAQUE_CSV = (
    "Col A,Col B,Device\n"
    "10.30.0.5,aa:bb:cc:00:00:05,PUMP-PLC\n"
    "10.30.0.6,aa:bb:cc:00:00:06,PUMP-HMI\n"
)


def _post(c, url, body, name="inv.csv", data=None, params=None):
    return c.post(url, params=params or {}, data=data or {},
                  files={"file": (name, body.encode(), "text/csv")})


def _site(c, code="s1"):
    r = c.post("/sites", json={"name": code.upper(), "code": code})
    assert r.status_code in (200, 201), r.text
    return code


# ----------------------------------------------------------------- unit --

def test_suggestions_by_name_alias_values_and_guess():
    headers = ["Asset Tag", "IP_Address", "MAC-Address", "Host Name", "Asset Type",
               "Purdue Level", "Vendor", "Notes"]
    s = {x["header"]: (x["suggested"], x["basis"]) for x in im.suggest_columns(headers, [])}
    assert s["IP_Address"] == ("ip", "alias")
    assert s["MAC-Address"] == ("mac", "alias")
    assert s["Host Name"] == ("hostname", "alias")
    assert s["Asset Type"] == ("device_type", "alias")
    assert s["Purdue Level"] == ("purdue_level", "exact")   # = the field name, spaced
    assert s["Vendor"] == (None, None) and s["Notes"] == (None, None)
    # a hostname alias already taken: "Asset Tag" (guess hostname) yields to "Host Name"
    assert s["Asset Tag"][0] is None
    # values beat a guess; a column of MACs with an opaque name is found
    rows = [r.split(",") for r in OPAQUE_CSV.splitlines()[1:]]
    o = {x["header"]: (x["suggested"], x["basis"]) for x in im.suggest_columns(["Col A", "Col B", "Device"], rows)}
    assert o["Col A"] == ("ip", "values") and o["Col B"] == ("mac", "values")
    assert o["Device"] == ("hostname", "guess")
    # the automatic mapping (uploads without a mapping) never applies values / guesses
    assert im.auto_map(["Col A", "Col B", "Device"]) == {"col a": "", "col b": "", "device": ""}
    # a saved mapping wins over the names, and "" keeps a column ignored
    saved = {"ip_address": "", "asset tag": "hostname", "host name": ""}
    s2 = {x["header"]: (x["suggested"], x["basis"]) for x in im.suggest_columns(headers, [], saved)}
    assert s2["Asset Tag"] == ("hostname", "saved") and s2["Host Name"] == (None, "saved")
    assert s2["IP_Address"] == (None, "saved")


def test_validate_column_map():
    h = ["ip", "addr", "name"]
    clean, errors, warnings = im.validate_column_map(h, {"ip": "ip", "addr": "ip", "zzz": "mac"})
    assert any("mapped from 2 columns" in e for e in errors)
    assert any("'zzz'" in w for w in warnings)
    _c, errors, _w = im.validate_column_map(h, {"name": "hostname"})
    assert any("IP address or MAC address" in e for e in errors)
    _c, errors, _w = im.validate_column_map(h, {"ip": "ip_addr"})
    assert any("unknown field" in e for e in errors)
    _c, errors, _w = im.validate_column_map(["IP", "ip"], {"ip": "ip"})
    assert any("Two columns are named 'ip'" in e for e in errors)
    clean, errors, _w = im.validate_column_map(h, {"IP": "ip"})
    assert not errors and clean == {"ip": "ip", "addr": "", "name": ""}


def test_known_device_type():
    assert im.known_device_type("PLC") == "plc"
    assert im.known_device_type("Engineering Workstation") == "engineering_workstation"
    assert im.known_device_type("site-scada-server") == "site_scada_server"
    assert im.known_device_type("Operator Panel") is None


def test_preview_checks():
    p = im.preview(VENDOR_CSV)
    assert p["errors"] == [] and p["can_import"]
    c = p["checks"]
    assert c["rows"] == 5 and c["would_import"] == 4
    assert c["no_identity"]["count"] == 1 and c["no_identity"]["rows"] == ["row 5"]
    assert c["invalid_purdue_level"]["count"] == 1 and "banana" in c["invalid_purdue_level"]["rows"][0]
    dt = c["device_types"]
    assert dt["unrecognised"] == {"Operator Panel": 1}
    assert dt["normalised"] == {"PLC": "plc", "Engineering Workstation": "engineering_workstation"}
    assert set(p["ignored_columns"]) == {"Asset Tag", "Vendor", "Notes"}
    assert any("device type value" in w for w in p["warnings"])
    cols = {x["header"]: x for x in p["columns"]}
    assert cols["IP_Address"]["samples"][:2] == ["10.20.1.11", "10.20.1.21"]
    assert cols["IP_Address"]["field"] == "ip"
    # a mapping without an identity column cannot be imported
    bad = im.preview(VENDOR_CSV, {"host name": "hostname"})
    assert not bad["can_import"] and bad["errors"]


# ------------------------------------------------------------------ API --

def test_preview_route_is_read_only_and_reports(tmp_path):
    with _api(tmp_path / "a.db") as c:
        code = _site(c)
        r = _post(c, "/ingest/baseline/asset-inventory/preview", VENDOR_CSV, params={"site": code})
        assert r.status_code == 200, r.text
        p = r.json()
        assert p["can_import"] and p["checks"]["would_import"] == 4
        assert {f["field"] for f in p["fields"]} >= {"ip", "mac", "hostname", "device_type"}
        assert p["saved_mapping"] is None
        assert c.get("/assets", params={"site": code}).json() == []        # nothing written
        # operator mapping previewed
        cm = json.dumps({"IP_Address": "ip", "Asset Tag": "hostname", "Host Name": ""})
        p2 = _post(c, "/ingest/baseline/asset-inventory/preview", VENDOR_CSV,
                   data={"column_map": cm}, params={"site": code}).json()
        assert p2["column_map"]["asset tag"] == "hostname" and p2["column_map"]["host name"] == ""
        assert p2["column_map"]["mac-address"] == ""                       # not in the map = ignored
        # bad input
        assert _post(c, "/ingest/baseline/asset-inventory/preview", VENDOR_CSV,
                     data={"column_map": "[1,2]"}, params={"site": code}).status_code == 422
        assert _post(c, "/ingest/baseline/asset-inventory/preview", VENDOR_CSV,
                     data={"column_map": "{not json"}, params={"site": code}).status_code == 422
        assert _post(c, "/ingest/baseline/asset-inventory/preview", "",
                     params={"site": code}).status_code == 422
        assert _post(c, "/ingest/baseline/asset-inventory/preview", VENDOR_CSV,
                     data={"mapping_id": "9999"}, params={"site": code}).status_code == 404
        assert c.post("/ingest/baseline/asset-inventory/preview",
                      params={"site": code}).status_code == 422


def test_mapped_import_saves_and_reuses_mapping(tmp_path):
    with _api(tmp_path / "b.db") as c:
        code = _site(c)
        # opaque headers: nothing maps by name, every row skipped and the problem reported
        r = _post(c, "/ingest/baseline/asset-inventory", OPAQUE_CSV, params={"site": code})
        st = r.json()["stats"]
        assert st["hosts_created_or_updated"] == 0 and st["skipped_no_identity"] == 2
        assert st["mapping_source"] == "names"
        assert set(st["columns_ignored"]) == {"col a", "col b", "device"}
        assert any("IP address or MAC address" in p for p in st["mapping_problems"])
        # the operator maps the columns and saves the mapping
        cm = json.dumps({"Col A": "ip", "Col B": "mac", "Device": "hostname"})
        bad = _post(c, "/ingest/baseline/asset-inventory", OPAQUE_CSV,
                    data={"column_map": json.dumps({"Device": "hostname"})}, params={"site": code})
        assert bad.status_code == 422 and bad.json()["detail"]["errors"]
        r = _post(c, "/ingest/baseline/asset-inventory", OPAQUE_CSV,
                  data={"column_map": cm, "save_mapping_as": "CMMS export", "saved_by": "pm"},
                  params={"site": code})
        assert r.status_code == 200, r.text
        j = r.json()
        assert j["stats"]["hosts_created_or_updated"] == 2 and j["stats"]["mapping_source"] == "supplied"
        assert j["stats"]["columns_mapped"] == {"col a": "ip", "col b": "mac", "device": "hostname"}
        assert j["mapping_saved"]["name"] == "CMMS export"
        hosts = {h["ip"]: h for h in c.get("/assets", params={"site": code}).json()}
        assert hosts["10.30.0.5"]["hostname"] == "PUMP-PLC"
        # listed
        lst = c.get("/ingest/baseline/asset-inventory/mappings", params={"site": code}).json()
        assert [m["name"] for m in lst["mappings"]] == ["CMMS export"] and lst["fields"]
        mid = lst["mappings"][0]["id"]
        # the next export from the same system maps itself: preview and plain upload
        nxt = OPAQUE_CSV.replace("PUMP-PLC", "PUMP-PLC-2")
        p = _post(c, "/ingest/baseline/asset-inventory/preview", nxt, params={"site": code}).json()
        assert p["saved_mapping"] == "CMMS export" and p["saved_mapping_id"] == mid
        assert {x["header"]: x["basis"] for x in p["columns"]} == {"Col A": "saved", "Col B": "saved",
                                                                  "Device": "saved"}
        r = _post(c, "/ingest/baseline/asset-inventory", nxt, params={"site": code}).json()
        assert r["stats"]["mapping_source"] == "saved:CMMS export"
        assert r["stats"]["hosts_created_or_updated"] == 2
        hosts = {h["ip"]: h for h in c.get("/assets", params={"site": code}).json()}
        assert hosts["10.30.0.5"]["hostname"] == "PUMP-PLC-2"
        # a file from another system does not pick it up
        other = _post(c, "/ingest/baseline/asset-inventory/preview", VENDOR_CSV,
                      params={"site": code}).json()
        assert other["saved_mapping"] is None
        # saving again under the same name updates it
        r = _post(c, "/ingest/baseline/asset-inventory", OPAQUE_CSV,
                  data={"column_map": json.dumps({"Col A": "ip", "Col B": "", "Device": "hostname"}),
                        "save_mapping_as": "CMMS export"}, params={"site": code}).json()
        lst = c.get("/ingest/baseline/asset-inventory/mappings", params={"site": code}).json()
        assert len(lst["mappings"]) == 1 and lst["mappings"][0]["column_map"]["col b"] == ""
        assert _post(c, "/ingest/baseline/asset-inventory", OPAQUE_CSV,
                     data={"column_map": cm, "save_mapping_as": "  "},
                     params={"site": code}).status_code == 422
        # another site does not see it and cannot delete it
        other_site = _site(c, "s2")
        assert c.get("/ingest/baseline/asset-inventory/mappings",
                     params={"site": other_site}).json()["mappings"] == []
        assert c.delete(f"/ingest/baseline/asset-inventory/mappings/{mid}",
                        params={"site": other_site}).status_code == 404
        p = _post(c, "/ingest/baseline/asset-inventory/preview", OPAQUE_CSV,
                  params={"site": other_site}).json()
        assert p["saved_mapping"] is None
        # delete
        assert c.delete(f"/ingest/baseline/asset-inventory/mappings/{mid}",
                        params={"site": code}).json() == {"deleted": mid}
        assert c.get("/ingest/baseline/asset-inventory/mappings",
                     params={"site": code}).json()["mappings"] == []


def test_plain_upload_reports_ignored_columns_and_normalises_types(tmp_path):
    with _api(tmp_path / "c.db") as c:
        code = _site(c)
        r = _post(c, "/ingest/baseline/asset-inventory", VENDOR_CSV, params={"site": code})
        st = r.json()["stats"]
        assert st["hosts_created_or_updated"] == 4 and st["skipped_no_identity"] == 1
        assert set(st["columns_ignored"]) == {"asset tag", "vendor", "notes"}
        assert st["columns_mapped"]["ip_address"] == "ip"
        assert st["device_type_normalised"] == 2              # "PLC", "Engineering Workstation"
        assert st["device_type_unrecognised"] == 1
        assert st["device_type_unrecognised_values"] == ["Operator Panel"]
        hosts = {h["ip"]: h for h in c.get("/assets", params={"site": code}).json()}
        assert hosts["10.20.1.11"]["device_type"] == "plc"
        assert hosts["10.20.1.31"]["device_type"] == "engineering_workstation"
        assert hosts["10.20.1.21"]["device_type"] == "Operator Panel"


@pytest.mark.parametrize("hdr", ["ip", "IP Address", "ip_address", "IPv4"])
def test_ip_header_variants_auto_map(hdr):
    assert im.auto_map([hdr])[im.column_key(hdr)] == "ip"

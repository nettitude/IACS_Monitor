"""
DNS and NTP server device types at L3 (site operations) and L4 (enterprise)
(owner, 2026-10-13: "for the Host Topology and other places that allow for
device types classifications. the L3 site operations and L4 should a DNS
server and NTP server choice").

The console's Classify control (Host Topology, Asset Inventory) and the
inventory import list device types from GET /purdue-levels, grouped by level.
"""
import pytest

from app.parsers.device_classification import DEVICE_TYPE_REFERENCE
from app.parsers.inventory_mapping import known_device_type

NEW = {"site_dns_server": 3, "site_ntp_server": 3, "enterprise_dns_server": 4, "enterprise_ntp_server": 4}


@pytest.mark.parametrize("dt,level", NEW.items())
def test_reference_levels(dt, level):
    assert DEVICE_TYPE_REFERENCE[dt][0] == level
    assert ("DNS" if "dns" in dt else "NTP") in DEVICE_TYPE_REFERENCE[dt][1]


def test_inventory_import_accepts_them():
    for k in NEW:
        assert known_device_type(k) == k


def test_listed_by_purdue_levels_route():
    from app.api.routes import get_purdue_levels
    body = get_purdue_levels()
    dt = {d["device_type"]: d["purdue_level"] for d in body["device_types"]}
    for k, lvl in NEW.items():
        assert dt[k] == lvl

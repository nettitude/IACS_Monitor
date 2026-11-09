"""
Switch config ingestion: VLAN assignment and CDP/LLDP neighbor discovery.

This is the physical-topology counterpart to pcap/ARP's logical (IP/MAC)
topology - it answers "what's plugged into what" and "which VLAN is
this port on", which pcap and ARP alone can't tell you.

Two switch vendors are supported, each with their own command syntax,
auto-detected from the text:

CISCO IOS
  1. Running-config interface blocks (VLAN + description per port):
         interface GigabitEthernet1/0/1
          description Uplink to Core
          switchport access vlan 10
          switchport mode access

  2. `show vlan brief` (VLAN -> port-list mapping, an alternate/
     complementary source for the same VLAN data):
         VLAN Name                             Status    Ports
         ---- -------------------------------- --------- -------------------
         10   ENGINEERING                      active    Gi1/0/1

  3. `show cdp neighbors detail` (Cisco-proprietary neighbor discovery):
         Device ID: PLC-SWITCH-01
         Platform: cisco WS-C2960X-24TS-L
         Interface: GigabitEthernet1/0/1, Port ID (outgoing port): GigabitEthernet0/1

  4. `show lldp neighbors detail` (Cisco's LLDP output format):
         Local Intf: Gi1/0/2
         Chassis id: 0011.2233.4455
         System Name: PLC-HMI-01

HP / ARUBA (ProCurve-style CLI - HP switches don't speak CDP, which is
Cisco-proprietary, so LLDP is the only neighbor-discovery source):
  5. Running-config VLAN blocks (note: HP puts VLAN membership under the
     `vlan <id>` block via `untagged`/`tagged` port lists, not on the
     interface itself - the inverse of Cisco's per-interface model):
         vlan 10
            name "ENGINEERING"
            untagged 1-4,6
         exit
         interface 1
            name "Uplink to Engineering Workstation"
         exit

  6. `show lldp info remote-device` (brief table):
         LocalPort | ChassisId               PortId   PortDescr SysName
         --------- + ------------------------ -------- --------- ----------
         1         | 00 00 00 12 34 ab        1        Port 1    plc-hmi-01

  7. `show lldp info remote-device <port>` (detail, one block per port):
         Local Port   : 1
         Chassis Id     : 00 00 00 12 34 ab
         Port Id        : 1
         System Name    : plc-hmi-01

All formats normalize into SwitchInterface rows, keyed on
(device_name, port_name), so VLAN data and neighbor data - almost always
captured in separate command outputs - merge onto the same port rather
than creating duplicate rows.
"""
import re
import logging
from typing import Optional

from sqlalchemy.orm import Session as DBSession

from app.sites import scope_site_id, site_ingest
from app.models import SwitchInterface, SwitchVlan
from app.parsers.common import normalize_mac

_DASH_LINE_RE = re.compile(r"^-{3,}\s*$")


# ============================================ CISCO running-config VLANs ==


log = logging.getLogger(__name__)

def _parse_cisco_vlan_name_blocks(text: str) -> dict:
    """
    Parse Cisco's separate global `vlan <id> / name <name>` blocks -
    distinct from the per-interface `switchport access/trunk vlan`
    commands parsed above. Cisco IOS supports defining a VLAN's name in
    this top-level block independently of which interfaces use it:

        vlan 10
         name ENGINEERING
        !
        vlan 20
         name ICS_CONTROL
        !

    Returns {vlan_id: name}. Any non-indented line (a new top-level
    stanza - "!", another "vlan N", "interface X", etc.) ends the
    current VLAN block's context, so a "name" line only attaches to the
    "vlan N" line immediately introducing it.
    """
    vlan_names = {}
    current_vlan = None
    for line in text.splitlines():
        vlan_match = re.match(r"^vlan\s+(\d+)\s*$", line)
        if vlan_match:
            current_vlan = vlan_match.group(1)
            continue
        if current_vlan and re.match(r"^\s+", line):
            name_match = re.match(r"^\s+name\s+(\S+)", line)
            if name_match:
                vlan_names[current_vlan] = name_match.group(1)
            continue
        current_vlan = None  # any other non-indented line ends this block's context
    return vlan_names


def parse_cisco_running_config_interfaces(text: str) -> tuple:
    """
    Parse Cisco IOS `interface <name> ... switchport ...` blocks from a
    running-config, plus separate global `vlan <id> / name <name>`
    blocks (see _parse_cisco_vlan_name_blocks) to attach a vlan_name to
    each access-mode port. Returns (hostname, list[dict]) - hostname is
    None if no `hostname <name>` line is present in the text.

    vlan_name is only attached for access-mode ports (exactly one VLAN
    applies, so its name is unambiguous) - trunk ports carry multiple
    VLANs in a comma-separated list, and no single name would be
    accurate, same treatment as the HP/ProCurve parser below.
    """
    hostname_match = re.search(r"^hostname\s+(\S+)", text, re.MULTILINE)
    hostname = hostname_match.group(1) if hostname_match else None

    vlan_names = _parse_cisco_vlan_name_blocks(text)

    interfaces = []
    current = None

    for line in text.splitlines():
        iface_match = re.match(r"^interface\s+(\S+)", line)
        if iface_match:
            if current:
                interfaces.append(current)
            current = {"port_name": iface_match.group(1), "vlan": None, "vlan_name": None, "mode": None, "description": None}
            continue

        if current is None:
            continue

        if re.match(r"^[ \t]*!\s*$", line):
            interfaces.append(current)
            current = None
            continue

        desc_match = re.match(r"\s*description\s+(.+)$", line)
        if desc_match:
            current["description"] = desc_match.group(1).strip()
            continue

        access_vlan_match = re.match(r"\s*switchport access vlan\s+(\d+)", line)
        if access_vlan_match:
            current["vlan"] = access_vlan_match.group(1)
            current["vlan_name"] = vlan_names.get(access_vlan_match.group(1))
            current["mode"] = "access"
            continue

        trunk_vlan_match = re.match(r"\s*switchport trunk allowed vlan\s+(\S+)", line)
        if trunk_vlan_match:
            current["vlan"] = trunk_vlan_match.group(1)  # e.g. "10,20-25,30"
            continue

        mode_match = re.match(r"\s*switchport mode\s+(\S+)", line)
        if mode_match:
            current["mode"] = mode_match.group(1)
            continue

    if current:
        interfaces.append(current)

    return hostname, interfaces


# ================================================== CISCO vlan brief ====

_VLAN_BRIEF_ROW_RE = re.compile(
    r"^(?P<vlan_id>\d+)\s+(?P<name>\S+)\s+(?P<status>\S+)\s*(?P<ports>.*)$"
)
_VLAN_BRIEF_CONTINUATION_RE = re.compile(r"^\s{2,}(?P<ports>[\w/,\s]+)$")


def parse_vlan_brief(text: str) -> list:
    """
    Parse `show vlan brief` output into per-VLAN port lists. Handles
    the common case of a wrapped port list continuing on the next line
    with only whitespace + port names (no VLAN id repeated) - a known
    quirk of this command's output when a VLAN has many ports.

    Limitation: doesn't attempt to reconcile this with running-config
    VLAN data beyond both feeding the same SwitchInterface rows later -
    if the two sources disagree (stale running-config vs. live vlan
    brief), the ingest order determines what's stored last.
    """
    entries = []
    last_vlan = None

    for line in text.splitlines():
        if not line.strip() or line.strip().startswith("VLAN") or _DASH_LINE_RE.match(line.strip()):
            continue

        row_match = _VLAN_BRIEF_ROW_RE.match(line)
        if row_match:
            ports = [p.strip() for p in row_match.group("ports").split(",") if p.strip()]
            entry = {
                "vlan_id": row_match.group("vlan_id"),
                "vlan_name": row_match.group("name"),
                "status": row_match.group("status"),
                "ports": ports,
            }
            entries.append(entry)
            last_vlan = entry
            continue

        continuation_match = _VLAN_BRIEF_CONTINUATION_RE.match(line)
        if continuation_match and last_vlan is not None:
            more_ports = [p.strip() for p in continuation_match.group("ports").split(",") if p.strip()]
            last_vlan["ports"].extend(more_ports)

    return entries


# ============================================ HP/PROCURVE running-config ==

def _expand_hp_port_list(port_list_str: str) -> list:
    """
    Expand an HP/ProCurve port-list expression into individual port
    names, e.g. "1-4,6" -> ["1","2","3","4","6"], or "A1-A4,B2" ->
    ["A1","A2","A3","A4","B2"] for modular/stacked switches that prefix
    ports with a module or stack-member letter.
    """
    ports = []
    for part in port_list_str.split(","):
        part = part.strip()
        if not part:
            continue
        range_match = re.match(r"^([A-Za-z]*)(\d+)-[A-Za-z]*(\d+)$", part)
        if range_match:
            prefix, start, end = range_match.group(1), int(range_match.group(2)), int(range_match.group(3))
            # AU full review E-M5: "1-999999999" in a crafted config used to
            # expand to a billion names; a real chassis has far fewer ports.
            if end < start or end > _HP_MAX_PORT or end - start + 1 > _HP_MAX_RANGE:
                log.warning("HP port range %r not expanded (out of bounds)", part)
                ports.append(part)
                continue
            ports.extend(f"{prefix}{n}" for n in range(start, end + 1))
        else:
            ports.append(part)
        if len(ports) > _HP_MAX_PORTS:
            log.warning("HP port list truncated at %d entries", _HP_MAX_PORTS)
            del ports[_HP_MAX_PORTS:]
            break
    return ports


_HP_MAX_PORT = 9_999        # highest port number a range may reach
_HP_MAX_RANGE = 1_024       # widest single range
_HP_MAX_PORTS = 4_096       # longest expanded list


def parse_hp_running_config_interfaces(text: str) -> tuple:
    """
    Parse HP/ProCurve running-config VLAN and interface blocks.

    Unlike Cisco, HP puts VLAN membership under the `vlan <id>` block
    (via `untagged`/`tagged` port lists) rather than on the interface
    itself - this function inverts that structure back into one entry
    per port, matching the shape `parse_cisco_running_config_interfaces`
    produces, so both feed the same downstream merge logic.

    A port that's `tagged` in one or more VLANs is treated as trunk mode
    (vlan field becomes a comma-joined list of all VLANs it carries,
    untagged one included if present); a port that's only `untagged` in
    exactly one VLAN is treated as access mode.
    """
    hostname_match = re.search(r'^hostname\s+"?([^"\n]+)"?\s*$', text, re.MULTILINE)
    hostname = hostname_match.group(1) if hostname_match else None

    vlan_blocks: dict = {}   # vlan_id -> {"name": str|None, "untagged": [...], "tagged": [...]}
    port_descriptions: dict = {}
    state = None
    current_id = None

    for line in text.splitlines():
        vlan_match = re.match(r"^[ \t]*vlan\s+(\d+)\s*$", line)
        if vlan_match:
            state, current_id = "vlan", vlan_match.group(1)
            vlan_blocks.setdefault(current_id, {"name": None, "untagged": [], "tagged": []})
            continue

        iface_match = re.match(r"^[ \t]*interface\s+(\S+)\s*$", line)
        if iface_match:
            state, current_id = "interface", iface_match.group(1)
            continue

        if re.match(r"^[ \t]*exit\s*$", line):
            state, current_id = None, None
            continue

        if state == "vlan" and current_id:
            name_match = re.match(r'^[ \t]*name\s+"?([^"\n]+)"?\s*$', line)
            if name_match:
                vlan_blocks[current_id]["name"] = name_match.group(1)
                continue
            untagged_match = re.match(r"^[ \t]*untagged\s+(\S+)", line)
            if untagged_match:
                vlan_blocks[current_id]["untagged"].extend(_expand_hp_port_list(untagged_match.group(1)))
                continue
            tagged_match = re.match(r"^[ \t]*tagged\s+(\S+)", line)
            if tagged_match:
                vlan_blocks[current_id]["tagged"].extend(_expand_hp_port_list(tagged_match.group(1)))
                continue

        elif state == "interface" and current_id:
            name_match = re.match(r'^[ \t]*name\s+"?([^"\n]+)"?\s*$', line)
            if name_match:
                port_descriptions[current_id] = name_match.group(1)
                continue

    # Invert vlan_id -> ports into port -> {vlan, mode}
    ports: dict = {}
    for vlan_id, membership in vlan_blocks.items():
        for port in membership["untagged"]:
            entry = ports.setdefault(
                port, {"port_name": port, "vlan": None, "vlan_name": None, "mode": None, "description": None, "_tagged": []}
            )
            entry["vlan"] = vlan_id
            # Only set vlan_name for access ports - exactly one VLAN
            # applies, so its name is unambiguous. Trunk ports (below)
            # carry multiple VLANs, so no single name would be accurate.
            entry["vlan_name"] = membership["name"]
            entry["mode"] = "access"
        for port in membership["tagged"]:
            entry = ports.setdefault(
                port, {"port_name": port, "vlan": None, "vlan_name": None, "mode": None, "description": None, "_tagged": []}
            )
            entry["_tagged"].append(vlan_id)
            entry["mode"] = "trunk"

    for entry in ports.values():
        if entry["mode"] == "trunk":
            combined = ([entry["vlan"]] if entry["vlan"] else []) + entry.pop("_tagged")
            entry["vlan"] = ",".join(combined)
            entry["vlan_name"] = None  # ambiguous which VLAN's name would apply - see comment above
        else:
            entry.pop("_tagged", None)

    for port, description in port_descriptions.items():
        entry = ports.setdefault(port, {"port_name": port, "vlan": None, "vlan_name": None, "mode": None, "description": None})
        entry["description"] = description

    return hostname, list(ports.values())


# ===================================================== CDP neighbors =====

def _split_neighbor_blocks(text: str) -> list:
    """Split CDP/LLDP 'detail' output on dashed separator lines."""
    blocks, current = [], []
    for line in text.splitlines():
        if _DASH_LINE_RE.match(line.strip()):
            if current:
                blocks.append("\n".join(current))
                current = []
            continue
        current.append(line)
    if current:
        blocks.append("\n".join(current))
    return [b for b in blocks if b.strip()]


def parse_cdp_neighbors(text: str) -> list:
    """
    Parse `show cdp neighbors detail` output. Each dash-separated block
    describes one neighbor relationship.
    """
    neighbors = []
    for block in _split_neighbor_blocks(text):
        device_match = re.search(r"Device ID:\s*(\S+)", block)
        if not device_match:
            continue  # not a neighbor block (e.g. leading command echo)

        platform_match = re.search(r"Platform:\s*([^,\n]+)", block)
        ip_match = re.search(r"IP address:\s*(\S+)", block)
        iface_match = re.search(
            r"Interface:\s*(\S+),\s*Port ID \(outgoing port\):\s*(\S+)", block
        )

        neighbors.append({
            "local_interface": iface_match.group(1) if iface_match else None,
            "neighbor_port": iface_match.group(2) if iface_match else None,
            # Some devices report their MAC as the CDP Device ID (e.g.
            # "0011.2233.4455"); store it canonically so it matches Host.mac.
            "neighbor_device": (normalize_mac(device_match.group(1))
                                if re.search(r"[.:-]", device_match.group(1)) else None)
                               or device_match.group(1),
            "neighbor_platform": platform_match.group(1).strip() if platform_match else None,
            "neighbor_ip": ip_match.group(1) if ip_match else None,
            "neighbor_protocol": "cdp",
        })

    return neighbors


# ================================================== CISCO LLDP neighbors ==

def parse_lldp_neighbors(text: str) -> list:
    """
    Parse Cisco's `show lldp neighbors detail` output. Chassis id is
    normalized as a MAC if it looks like one (the common case for
    switches/PLCs that don't set a separate management address); left
    as-is otherwise (LLDP permits chassis id to be an interface name or
    locally-assigned string instead of a MAC).
    """
    neighbors = []
    for block in _split_neighbor_blocks(text):
        local_intf_match = re.search(r"Local Intf:\s*(\S+)", block)
        if not local_intf_match:
            continue

        chassis_match = re.search(r"Chassis id:\s*(\S+)", block)
        port_match = re.search(r"Port id:\s*(\S+)", block)
        name_match = re.search(r"System Name:\s*(\S+)", block)
        ip_match = re.search(r"IP:\s*(\S+)", block)

        chassis_id = chassis_match.group(1) if chassis_match else None
        normalized_chassis = normalize_mac(chassis_id) if chassis_id else None

        neighbors.append({
            "local_interface": local_intf_match.group(1),
            "neighbor_port": port_match.group(1) if port_match else None,
            "neighbor_device": name_match.group(1) if name_match else (normalized_chassis or chassis_id),
            "neighbor_platform": None,  # LLDP detail's "System Description" varies too much to parse reliably
            "neighbor_ip": ip_match.group(1) if ip_match else None,
            "neighbor_protocol": "lldp",
        })

    return neighbors


# =================================================== HP/PROCURVE LLDP ====

def parse_hp_lldp_brief(text: str) -> list:
    """
    Parse HP/ProCurve `show lldp info remote-device` brief table output:

        LocalPort | ChassisId               PortId   PortDescr SysName
        --------- + ------------------------ -------- --------- ----------
        1         | 00 00 00 12 34 ab        1        Port 1    plc-hmi-01

    Column widths vary by content, so rows are split on the literal `|`
    for the local port, then on runs of 2+ spaces for the remaining
    columns rather than fixed offsets.
    """
    neighbors = []
    for line in text.splitlines():
        if "|" not in line:
            continue
        stripped = line.strip()
        if stripped.startswith("LocalPort") or stripped.startswith("-"):
            continue  # header or header-separator row

        local_part, rest = line.split("|", 1)
        local_port = local_part.strip()
        if not local_port:
            continue

        fields = [f for f in re.split(r"\s{2,}", rest.strip()) if f]
        if len(fields) < 2:
            continue  # malformed row - not enough columns to be useful

        chassis_id = fields[0]
        port_id = fields[1] if len(fields) > 1 else None
        sysname = fields[-1] if len(fields) > 2 else None
        normalized_chassis = normalize_mac(chassis_id)

        neighbors.append({
            "local_interface": local_port,
            "neighbor_port": port_id,
            "neighbor_device": sysname or normalized_chassis or chassis_id,
            "neighbor_platform": None,
            "neighbor_ip": None,
            "neighbor_protocol": "lldp",
        })

    return neighbors


def parse_hp_lldp_detail(text: str) -> list:
    """
    Parse HP/ProCurve `show lldp info remote-device <port>` detail output,
    one block per local port, e.g.:

        Local Port   : 1
        Chassis Id     : 00 00 00 12 34 ab
        Port Id        : 1
        System Name    : plc-hmi-01
        Remote Management Address
             Type    : ipv4
             Address : 10.0.1.10

    Blocks are split at each "Local Port" line rather than on a
    separator line, since HP's detail output doesn't use dashed
    separators between ports the way Cisco's does.
    """
    neighbors = []
    blocks = re.split(r"(?=^[ \t]*Local Port\s*:)", text, flags=re.MULTILINE)

    for block in blocks:
        local_port_match = re.search(r"Local Port\s*:\s*(\S+)", block)
        if not local_port_match:
            continue

        chassis_match = re.search(r"Chassis Id\s*:\s*(.+)", block)
        port_match = re.search(r"Port Id\s*:\s*(\S+)", block)
        name_match = re.search(r"System Name\s*:\s*(\S+)", block)
        ip_match = re.search(r"Address\s*:\s*(\S+)", block)

        chassis_id = chassis_match.group(1).strip() if chassis_match else None
        normalized_chassis = normalize_mac(chassis_id) if chassis_id else None

        neighbors.append({
            "local_interface": local_port_match.group(1),
            "neighbor_port": port_match.group(1) if port_match else None,
            "neighbor_device": name_match.group(1) if name_match else (normalized_chassis or chassis_id),
            "neighbor_platform": None,
            "neighbor_ip": ip_match.group(1) if ip_match else None,
            "neighbor_protocol": "lldp",
        })

    return neighbors


# ========================================================== dispatch ====

def detect_switch_config_type(text: str, vendor_hint: Optional[str] = None) -> str:
    """
    Returns one of "running_config" (Cisco), "vlan_brief" (Cisco),
    "cdp_neighbors" (Cisco), "lldp_neighbors" (Cisco), "hp_running_config",
    "hp_lldp_brief", "hp_lldp_detail", or "unknown".

    `vendor_hint` ("cisco" or "hp") scopes detection to that vendor's
    sub-formats only - the intended path when the UI already asked the
    person which vendor this switch is, so it only needs to ask "which
    vendor", not also "which specific `show` command output" (the
    sub-format is still auto-detected from the four-or-so possibilities
    within that vendor's family). An unrecognized or missing hint falls
    back to detecting across both vendors.

    Detection order matters when no hint is given:
      - CDP/LLDP detail output is checked before the looser
        running-config/vlan-brief patterns since "Interface:" (CDP)
        could otherwise false-match a running-config heuristic.
      - HP's running-config check is placed before Cisco's, since both
        use bare `interface <name>` lines - HP is disambiguated by its
        distinctive `vlan <id>` block containing `untagged`/`tagged`
        keywords, vocabulary Cisco IOS never uses (Cisco expresses the
        same thing per-interface via `switchport access/trunk vlan`).
    """
    vendor_hint = (vendor_hint or "").strip().lower() or None
    if vendor_hint == "fortinet" or (vendor_hint is None and any(r.search(text) for r in _FORTINET_SIGNATURES)):
        return "fortinet_running_config" if any(r.search(text) for r in _FORTINET_SIGNATURES) else "unknown"
    if vendor_hint == "cisco":
        if re.search(r"Device ID:", text):
            return "cdp_neighbors"
        if re.search(r"Local Intf:", text):
            return "lldp_neighbors"
        if re.search(r"^VLAN\s+Name\s+Status", text, re.MULTILINE):
            return "vlan_brief"
        if re.search(r"^interface\s+\S+", text, re.MULTILINE):
            return "running_config"
        return "unknown"

    if vendor_hint == "hp":
        if re.search(r"^[ \t]*Local Port\s*:", text, re.MULTILINE):
            return "hp_lldp_detail"
        if re.search(r"LocalPort\s*\|", text):
            return "hp_lldp_brief"
        if (
            re.search(r"^[ \t]*vlan\s+\d+\s*$", text, re.MULTILINE)
            or re.search(r"^[ \t]*(untagged|tagged)\s+", text, re.MULTILINE)
        ):
            return "hp_running_config"
        return "unknown"

    # No hint (or an unrecognized one) - detect across both vendors.
    if re.search(r"Device ID:", text):
        return "cdp_neighbors"
    if re.search(r"^[ \t]*Local Port\s*:", text, re.MULTILINE):
        return "hp_lldp_detail"
    if re.search(r"LocalPort\s*\|", text):
        return "hp_lldp_brief"
    if re.search(r"Local Intf:", text):
        return "lldp_neighbors"
    if re.search(r"^VLAN\s+Name\s+Status", text, re.MULTILINE):
        return "vlan_brief"
    if (
        re.search(r"^[ \t]*vlan\s+\d+\s*$", text, re.MULTILINE)
        and re.search(r"^[ \t]*(untagged|tagged)\s+", text, re.MULTILINE)
    ):
        return "hp_running_config"
    if re.search(r"^interface\s+\S+", text, re.MULTILINE):
        return "running_config"
    return "unknown"


# ------------------------------------------------ vendor mismatch (N-24) ---

_VENDOR_LABEL = {"cisco": "Cisco IOS", "hp": "HP/ProCurve"}


class VendorMismatchError(ValueError):
    """The uploaded content clearly belongs to a different vendor than the
    caller's ``vendor_hint`` (e.g. an HP/ProCurve config sent with
    ``vendor_hint=cisco``).  Raised before anything is written; the API maps
    it to HTTP 422."""

    def __init__(self, hint: str, detected: str):
        self.hint = hint
        self.detected = detected
        super().__init__(
            f"vendor_hint={hint!r} does not match the uploaded content, which "
            f"looks like {_VENDOR_LABEL.get(detected, detected)} output. Re-upload "
            f"with vendor_hint={detected!r} (or omit vendor_hint to auto-detect)."
        )


# Signatures that only one vendor's output contains.
_HP_SIGNATURES = (
    re.compile(r"^[ \t]*(untagged|tagged)\s+\S", re.MULTILINE),
    re.compile(r"LocalPort\s*\|"),
    re.compile(r"^[ \t]*Local Port\s*:", re.MULTILINE),
    re.compile(r"^;.*Configuration Editor", re.MULTILINE),
)
_FORTINET_SIGNATURES = (
    re.compile(r"^config switch (interface|physical-port|vlan|trunk)\b", re.MULTILINE),
    re.compile(r"^#config-version=FS", re.MULTILINE),
)
_CISCO_SIGNATURES = (
    re.compile(r"Device ID:"),
    re.compile(r"Local Intf:"),
    re.compile(r"^VLAN\s+Name\s+Status", re.MULTILINE),
    re.compile(r"^[ \t]*switchport\b", re.MULTILINE),
    re.compile(r"^interface\s+(?:Gigabit|Fast|Ten|Forty|Ethernet|Vlan|Port-channel|Loopback|Gi\d|Fa\d|Te\d)",
               re.MULTILINE | re.IGNORECASE),
    re.compile(r"^spanning-tree mode\b", re.MULTILINE),
    re.compile(r"^version\s+\d", re.MULTILINE),
)


def detect_switch_vendor(text: str) -> Optional[str]:
    """"cisco" / "hp" when the content carries only that vendor's signatures,
    else None (no signature, or ambiguous)."""
    hp = any(r.search(text) for r in _HP_SIGNATURES)
    cisco = any(r.search(text) for r in _CISCO_SIGNATURES)
    fortinet = any(r.search(text) for r in _FORTINET_SIGNATURES)
    if fortinet and not (hp or cisco):
        return "fortinet"
    if hp and not cisco and not fortinet:
        return "hp"
    if cisco and not hp and not fortinet:
        return "cisco"
    return None


def check_vendor_hint(text: str, vendor_hint: Optional[str]) -> None:
    """Raise VendorMismatchError if a "cisco"/"hp" hint contradicts the content."""
    vendor_hint = (vendor_hint or "").strip().lower()
    if vendor_hint not in ("cisco", "hp", "fortinet"):
        return
    detected = detect_switch_vendor(text)
    if detected is not None and detected != vendor_hint:
        raise VendorMismatchError(vendor_hint, detected)


def _vlan_tokens(v) -> list:
    """FortiSwitchOS VLAN lists: `20,30`, `"20" "30"`, `20-25` -> ["20", "30", ...]."""
    out = []
    for tok in (v if isinstance(v, (list, tuple)) else [v]):
        for part in str(tok).strip('"').split(","):
            part = part.strip()
            if not part:
                continue
            m = re.fullmatch(r"(\d+)-(\d+)", part)
            if m:
                out += [str(x) for x in range(int(m.group(1)), int(m.group(2)) + 1)]
            elif "-" in part:
                continue                    # "20-" / "-5": malformed, skipped (audit 2026-10-19)
            else:
                out.append(part)
    return out


def parse_fortinet_switch_config(text: str) -> tuple:
    """Standalone FortiSwitchOS `show full-configuration` (owner 2026-10-19):
    (hostname, interfaces, vlans).  ``interfaces`` = [{port_name, mode, vlan,
    vlan_name, description, admin_status, port_security_policy, uplink}];
    ``vlans`` = {vlan id: name}.  `config switch interface` carries native /
    allowed VLANs and `security-mode`, `config switch physical-port` the admin
    state and description, `config switch trunk` the LAG uplinks, `config
    switch vlan` the names."""
    from app.parsers.forti_config_parser import parse_forti_block
    parsed = parse_forti_block(text)

    def _s(d, k, default=""):
        v = d.get(k, default)
        v = v[0] if isinstance(v, (list, tuple)) and v else v
        return str(v if v is not None else default).strip('"')
    hostname = _s(parsed.get("system global") or {}, "hostname") or None
    vlans = {}
    for vid, vc in (parsed.get("switch vlan") or {}).items():
        if isinstance(vc, dict):
            vlans[str(vid).strip('"')] = _s(vc, "description") or None
    phys = {str(n).strip('"'): c for n, c in (parsed.get("switch physical-port") or {}).items() if isinstance(c, dict)}
    trunk_members: set = set()
    trunks: set = set()
    for tn, tc in (parsed.get("switch trunk") or {}).items():
        if isinstance(tc, dict):
            trunks.add(str(tn).strip('"'))
            trunk_members |= {str(m).strip('"') for m in (tc.get("members") if isinstance(tc.get("members"), (list, tuple)) else [tc.get("members")]) if m}
    interfaces = []
    for iname, ic in (parsed.get("switch interface") or {}).items():
        if not isinstance(ic, dict):
            continue
        name = str(iname).strip('"')
        native = _s(ic, "native-vlan") or None
        allowed = [a for a in _vlan_tokens(ic.get("allowed-vlans")) if a != native] if ic.get("allowed-vlans") else []
        uplink = name in trunks or name in trunk_members or name.lower().startswith("__fortilink") or _s(ic, "fortilink-port", "disable") == "enable"
        mode = "trunk" if (allowed or uplink or _s(ic, "allowed-vlans-all", "disable") == "enable") else "access"
        sec = _s(ic, "security-mode", "none")
        # owner 2026-11-09: `config port-security` under the interface says whether the mode admits
        # unauthenticated devices (open-auth) or falls back to MAC authentication bypass
        psec = ic.get("port-security") if isinstance(ic.get("port-security"), dict) else {}
        if sec in ("", "none"):
            sec_mode = None
        elif _s(psec, "open-auth", "disable") == "enable":
            sec_mode = "open-auth"
        elif _s(psec, "mac-auth-bypass", "disable") == "enable" or "mac-based" in sec.lower():
            sec_mode = "802.1x-mab"
        else:
            sec_mode = "802.1x"
        pc = phys.get(name) or {}
        interfaces.append({"port_name": name, "mode": mode, "port_security_mode": sec_mode,
                           "vlan": ("all" if _s(ic, "allowed-vlans-all", "disable") == "enable" else ",".join(sorted({*([native] if native else []), *allowed}, key=lambda x: int(x) if x.isdigit() else 0))) if mode == "trunk" else native,
                           "vlan_name": (vlans.get(native) if native else None) if mode == "access" else None,
                           "description": _s(ic, "description") or _s(pc, "description") or None,
                           "admin_status": _s(pc, "status", "up") or "up",
                           "port_security_policy": None if sec in ("", "none") else sec, "uplink": uplink})
    return hostname, interfaces, vlans


# ------------------------------------------------------------- ingest ---

def _get_or_create_switch_interface(
    db: DBSession, device_name: Optional[str], port_name: str
) -> SwitchInterface:
    sid = scope_site_id(db)  # phase 2: switch rows are per site
    query = db.query(SwitchInterface).filter(SwitchInterface.site_id == sid,
                                             SwitchInterface.port_name == port_name)
    query = query.filter(SwitchInterface.device_name == device_name) if device_name else query.filter(
        SwitchInterface.device_name.is_(None)
    )
    iface = query.first()
    if iface:
        return iface

    iface = SwitchInterface(site_id=sid, device_name=device_name, port_name=port_name)
    db.add(iface)
    db.flush()
    return iface


def _upsert_switch_vlan(
    db: DBSession,
    device_name: Optional[str],
    vlan_id_str: str,
    vlan_name: Optional[str],
    status: Optional[str],
    port_count: Optional[int],
    source_file: Optional[str],
) -> None:
    """
    Write (or update) one SwitchVlan row.  Seeds purdue_level via keyword
    inference on the VLAN name if no manual level exists yet.  Never
    overwrites a manually-set purdue_level.
    """
    # Lazy import to avoid a top-level circular-import risk in test setups
    # that stub models before parsers load.  device_classification only
    # imports from app.models, so this is a clean one-way dependency.
    from app.parsers.device_classification import classify_vlan_name  # noqa: PLC0415

    try:
        vlan_id_int = int(vlan_id_str)
    except (ValueError, TypeError):
        return  # malformed vlan_id; skip silently

    sid = scope_site_id(db)  # phase 2: switch rows are per site
    existing = (
        db.query(SwitchVlan)
        .filter(SwitchVlan.site_id == sid, SwitchVlan.device_name == device_name,
                SwitchVlan.vlan_id == vlan_id_int)
        .first()
    )
    if existing is None:
        existing = SwitchVlan(site_id=sid, device_name=device_name, vlan_id=vlan_id_int)
        db.add(existing)

    # Always refresh name/status/port_count and source_file
    if vlan_name is not None:
        existing.vlan_name = vlan_name
    if status is not None:
        existing.status = status
    if port_count is not None:
        existing.port_count = port_count
    existing.source_file = source_file

    # Seed purdue_level from keyword inference, but never overwrite manual.
    if existing.purdue_level_source != "manual":
        inferred = classify_vlan_name(existing.vlan_name)
        if inferred is not None:
            existing.purdue_level = inferred
            existing.purdue_level_source = "keyword_inferred"


def _hardening(db, text, device, vendor, source_file) -> dict:
    """G-03: SNMP community / telnet findings of a running-config.  Never
    fails the ingest."""
    from app.parsers.switch_hardening import check_switch_config
    try:
        return check_switch_config(db, text, device, vendor, source_file)
    except Exception:                                   # noqa: BLE001
        log.exception("switch hardening checks failed for %s", device)
        return {"error": "switch hardening checks failed; see the server log"}


@site_ingest  # multi-site: keyword-only site_id (app.sites)
def ingest_switch_config(
    text: str,
    db: DBSession,
    device_name: Optional[str] = None,
    source_file: Optional[str] = None,
    vendor_hint: Optional[str] = None,
) -> dict:
    """
    Parse a switch config/command-output file and merge results into
    SwitchInterface rows. `device_name` can be passed explicitly (e.g.
    from a filename convention like "core-switch-1_cdp.txt") to
    associate CDP/LLDP output - which has no hostname of its own for the
    *local* device - with the right switch; running-config text can
    supply its own hostname via the `hostname` line. `vendor_hint`
    ("cisco" or "hp") scopes format detection to that vendor - see
    `detect_switch_config_type` for details.
    """
    check_vendor_hint(text, vendor_hint)  # N-24: reject, don't mis-parse
    config_type = detect_switch_config_type(text, vendor_hint=vendor_hint)
    stats = {"config_type": config_type, "interfaces_touched": 0, "vendor_hint_used": vendor_hint}

    if config_type == "running_config":
        hostname, interfaces = parse_cisco_running_config_interfaces(text)
        effective_device = device_name or hostname
        # Collect unique (vlan_id, vlan_name) pairs from the global vlan blocks
        # embedded in the running-config (re-parsed here so the ingest call has
        # access to them without changing parse_cisco_running_config_interfaces's
        # return type).
        cisco_vlan_names = _parse_cisco_vlan_name_blocks(text)
        for vlan_id_str, vname in cisco_vlan_names.items():
            _upsert_switch_vlan(
                db, effective_device, vlan_id_str, vname, None, None, source_file
            )
        for iface_data in interfaces:
            iface = _get_or_create_switch_interface(db, effective_device, iface_data["port_name"])
            iface.vlan = iface_data["vlan"]
            iface.vlan_name = iface_data.get("vlan_name")
            iface.mode = iface_data["mode"]
            iface.description = iface_data["description"]
            iface.source_file = source_file
            stats["interfaces_touched"] += 1
        stats["hardening"] = _hardening(db, text, effective_device, "cisco", source_file)
        # LS-01: ip routing + SVIs -> the switch is a routing enforcement point
        # (inside a SAVEPOINT: a failure there never loses the interfaces,
        # VLANs and hardening findings of this upload)
        try:
            from app.parsers.l3_switch import sync_switch
            with db.begin_nested():
                stats["l3"] = sync_switch(db, effective_device, text, source_file)
        except Exception:                               # noqa: BLE001
            log.exception("L3 switch model failed for %s", effective_device)
            stats["l3"] = {"error": "L3 switch model failed; see the server log"}

    elif config_type == "fortinet_running_config":
        # owner 2026-10-19: standalone FortiSwitchOS configuration (FortiLink-managed switches come
        # with the FortiGate backup instead - app/parsers/fortiswitch_parser.py)
        hostname, interfaces, vlans = parse_fortinet_switch_config(text)
        effective_device = device_name or hostname
        counts: dict = {}
        for iface_data in interfaces:
            for vid in (iface_data["vlan"] or "").split(","):
                if vid and vid != "all":
                    counts[vid] = counts.get(vid, 0) + 1
        for vid in sorted(set(vlans) | set(counts), key=lambda x: int(x) if x.isdigit() else 0):
            _upsert_switch_vlan(db, effective_device, vid, vlans.get(vid), "active", counts.get(vid), source_file)
        for iface_data in interfaces:
            iface = _get_or_create_switch_interface(db, effective_device, iface_data["port_name"])
            iface.vlan = iface_data["vlan"]
            iface.vlan_name = iface_data.get("vlan_name")
            iface.mode = iface_data["mode"]
            iface.description = iface_data["description"]
            iface.admin_status = iface_data["admin_status"]
            iface.port_security_policy = iface_data["port_security_policy"]
            iface.port_security_mode = iface_data.get("port_security_mode")
            iface.uplink = bool(iface_data["uplink"])
            iface.source_file = f"fortiswitch:{source_file or effective_device}"
            stats["interfaces_touched"] += 1
        stats["vlans"] = len(set(vlans) | set(counts))
        stats["hardening"] = _hardening(db, text, effective_device, "fortinet", source_file)

    elif config_type == "hp_running_config":
        hostname, interfaces = parse_hp_running_config_interfaces(text)
        effective_device = device_name or hostname
        # Extract unique (vlan_id, vlan_name) pairs from access-mode ports
        # (trunk ports set vlan_name=None intentionally, so skip those).
        seen_vlans: dict = {}
        for iface_data in interfaces:
            vid = iface_data.get("vlan")
            vname = iface_data.get("vlan_name")
            if vid and vname and vid not in seen_vlans:
                seen_vlans[vid] = vname
        for vlan_id_str, vname in seen_vlans.items():
            _upsert_switch_vlan(
                db, effective_device, vlan_id_str, vname, None, None, source_file
            )
        for iface_data in interfaces:
            iface = _get_or_create_switch_interface(db, effective_device, iface_data["port_name"])
            iface.vlan = iface_data["vlan"]
            iface.vlan_name = iface_data.get("vlan_name")
            iface.mode = iface_data["mode"]
            iface.description = iface_data["description"]
            iface.source_file = source_file
            stats["interfaces_touched"] += 1
        stats["hardening"] = _hardening(db, text, effective_device, "hp", source_file)

    elif config_type == "vlan_brief":
        vlan_entries = parse_vlan_brief(text)
        for entry in vlan_entries:
            # vlan_brief is the authoritative source for status and port count -
            # previously both were silently discarded; now persisted in SwitchVlan.
            _upsert_switch_vlan(
                db, device_name,
                entry["vlan_id"], entry["vlan_name"],
                entry.get("status"),
                len(entry["ports"]),
                source_file,
            )
            for port in entry["ports"]:
                iface = _get_or_create_switch_interface(db, device_name, port)
                iface.vlan = entry["vlan_id"]
                iface.vlan_name = entry["vlan_name"]
                iface.source_file = source_file
                stats["interfaces_touched"] += 1

    elif config_type == "cdp_neighbors":
        for neighbor in parse_cdp_neighbors(text):
            if not neighbor["local_interface"]:
                continue
            iface = _get_or_create_switch_interface(db, device_name, neighbor["local_interface"])
            iface.neighbor_device = neighbor["neighbor_device"]
            iface.neighbor_port = neighbor["neighbor_port"]
            iface.neighbor_platform = neighbor["neighbor_platform"]
            iface.neighbor_ip = neighbor["neighbor_ip"]
            iface.neighbor_protocol = neighbor["neighbor_protocol"]
            iface.source_file = source_file
            stats["interfaces_touched"] += 1

    elif config_type == "lldp_neighbors":
        for neighbor in parse_lldp_neighbors(text):
            iface = _get_or_create_switch_interface(db, device_name, neighbor["local_interface"])
            iface.neighbor_device = neighbor["neighbor_device"]
            iface.neighbor_port = neighbor["neighbor_port"]
            iface.neighbor_platform = neighbor["neighbor_platform"]
            iface.neighbor_ip = neighbor["neighbor_ip"]
            iface.neighbor_protocol = neighbor["neighbor_protocol"]
            iface.source_file = source_file
            stats["interfaces_touched"] += 1

    elif config_type in ("hp_lldp_brief", "hp_lldp_detail"):
        parser_fn = parse_hp_lldp_brief if config_type == "hp_lldp_brief" else parse_hp_lldp_detail
        for neighbor in parser_fn(text):
            iface = _get_or_create_switch_interface(db, device_name, neighbor["local_interface"])
            iface.neighbor_device = neighbor["neighbor_device"]
            iface.neighbor_port = neighbor["neighbor_port"]
            iface.neighbor_platform = neighbor["neighbor_platform"]
            iface.neighbor_ip = neighbor["neighbor_ip"]
            iface.neighbor_protocol = neighbor["neighbor_protocol"]
            iface.source_file = source_file
            stats["interfaces_touched"] += 1

    db.commit()
    return stats

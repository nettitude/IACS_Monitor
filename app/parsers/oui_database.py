"""
Wireshark `manuf` file support.

Grassmarlin does not ship its own MAC OUI/vendor database. Its own
source (GM3/src/util/Launcher.java, GM3/src/core/Configuration.java)
shows it loads Wireshark's `manuf` file directly - resolving
PATH_MANUFACTURER_DB to a `manuf` file next to the configured Wireshark
executable, and explicitly disabling MAC lookup with a warning if that
file can't be found. There's no separate curated ICS-vendor OUI list to
pull in; "Grassmarlin's OUI data" and "Wireshark's OUI data" are the
same file.

This module lets IACS_Monitor load that exact file format directly, as
a pluggable alternative to scapy's bundled `conf.manufdb` (which is
also ultimately IEEE/Wireshark-derived, but may be an older or less
complete snapshot than a manuf file pulled from an actual Grassmarlin
or current Wireshark installation). Practical ways to get one:

  - Copy it from a Grassmarlin or Wireshark installation directory
    (historically shipped as a plain-text file next to the Wireshark
    executable).
  - Wireshark 4+ replaced the on-disk text file with compiled-in binary
    data; regenerate a text copy with `tshark -G manuf > manuf`.
  - Pull the plain-text version bundled with older Wireshark releases
    (pre-4.0) or a source mirror of `manuf.tmpl`, if that vintage is
    acceptable for your use.

FILE FORMAT (confirmed against Wireshark's own documentation and
several independent open-source parsers - coolbho3k/manuf, netcrawl -
which all agree on the algorithm below):

    XX:XX:XX            ShortName    Full Vendor Name
    XX:XX:XX:XX:XX/40   ShortName    Full Vendor Name    # optional comment

  - Whitespace-separated fields; `#` starts a comment.
  - The first field is a MAC prefix (colon/dash/dot separated, any
    length from a 3-byte OUI up to a full 6-byte address), optionally
    followed by `/<significant-bits>` for a mask that isn't a whole
    number of bytes (verified against Wireshark's own documented
    example: a `/40`-masked entry matches all addresses sharing its
    first 5 bytes, wildcarding only the 6th).
  - Longest-prefix-match wins when multiple entries could apply (e.g. a
    specific 5-byte masked entry takes precedence over a broader 3-byte
    OUI entry covering the same address) - implemented here as the
    same "iterate mask-lengths from most to least specific, return the
    first hit" algorithm used by the reference parsers, and verified
    against the exact worked example from Wireshark's own man page
    before being relied on.
"""
import re
from typing import Optional

_HEX_CHARS = set("0123456789abcdef")


def _mac_str_to_int(mac_str: str) -> int:
    """Convert a MAC prefix string (any separator, any length) to a
    48-bit integer, right-padded with zero bits for a partial prefix."""
    hex_only = "".join(ch for ch in mac_str.lower() if ch in _HEX_CHARS)
    return int(hex_only.ljust(12, "0"), 16)


def _bits_left_from_str(mac_str: str) -> int:
    """How many low-order bits are NOT specified by this prefix string,
    based purely on how many hex digits were given (before any explicit
    /mask is applied)."""
    hex_only = "".join(ch for ch in mac_str.lower() if ch in _HEX_CHARS)
    return 48 - (len(hex_only) * 4)


def parse_manuf_text(text: str) -> dict:
    """
    Parse manuf-format text into a lookup table keyed by
    (bits_left, prefix_int >> bits_left) -> (short_name, long_name),
    ready for use with `lookup_manuf`.
    """
    entries: dict = {}

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        code_part, _, comment_part = line.partition("#")
        fields = code_part.split()
        if len(fields) < 2:
            continue

        prefix_field = fields[0]
        short_name = fields[1]
        long_name = " ".join(fields[2:]).strip() if len(fields) > 2 else None
        if not long_name and comment_part.strip():
            long_name = comment_part.strip()

        prefix_str, has_mask, mask_suffix = prefix_field.partition("/")
        bits_left = _bits_left_from_str(prefix_str)

        if has_mask:
            try:
                explicit_significant_bits = int(mask_suffix)
                explicit_bits_left = 48 - explicit_significant_bits
                # An explicit mask is authoritative for how many bits
                # actually matter - it can only make the entry AS OR
                # MORE general than the raw byte count would suggest
                # (a mask never adds precision beyond what bytes were
                # literally written), so take whichever is less specific.
                bits_left = max(bits_left, explicit_bits_left)
            except ValueError:
                pass  # malformed mask suffix - fall back to byte-count-derived bits_left

        mac_int = _mac_str_to_int(prefix_str)
        entries[(bits_left, mac_int >> bits_left)] = (short_name, long_name)

    return entries


def lookup_manuf(mac_normalized: str, entries: dict) -> Optional[str]:
    """
    Look up a normalized (aa:bb:cc:dd:ee:ff) MAC address in a table
    built by `parse_manuf_text`, using longest-prefix-match (most
    specific entry wins). Returns the long vendor name if present,
    else the short name, else None if nothing matches.
    """
    hex_only = mac_normalized.replace(":", "")
    if len(hex_only) != 12:
        return None

    mac_int = int(hex_only, 16)
    for bits_left in range(0, 48):
        match = entries.get((bits_left, mac_int >> bits_left))
        if match:
            short_name, long_name = match
            return long_name or short_name
    return None


def load_manuf_file(path: str) -> dict:
    """Convenience wrapper: read a manuf file from disk and parse it."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return parse_manuf_text(f.read())


# ---------------------------------------------------------------------------
# MAC address kind (F-16)
# ---------------------------------------------------------------------------
# Bit 0 of the first octet is the I/G (individual/group) bit: set for
# multicast and broadcast.  Bit 1 is the U/L bit: set for locally
# administered addresses - randomised/private MACs (iOS/Android/Windows
# privacy addresses), VM and container NICs, many virtual routers.  Neither
# kind is assigned from an IEEE OUI, so a manuf-table "match" on the first
# three octets of such an address names an unrelated vendor (or a generic
# label such as "IPv4mcast") and must not be reported as the device maker.
MAC_KIND_UNIVERSAL = "universal"
MAC_KIND_LOCAL = "locally_administered"
MAC_KIND_MULTICAST = "multicast"


def mac_kind(mac: Optional[str]) -> Optional[str]:
    """
    Classify a MAC address as "universal" (IEEE OUI-assigned),
    "locally_administered" (U/L bit set: randomised/virtual) or
    "multicast" (I/G bit set; includes broadcast). Accepts any common
    notation (only the first octet's hex digits are inspected); returns
    None for anything that isn't 12 hex digits.
    """
    if not mac:
        return None
    hex_only = "".join(ch for ch in mac.lower() if ch in _HEX_CHARS)
    if len(hex_only) != 12:
        return None
    first = int(hex_only[0:2], 16)
    if first & 0x01:
        return MAC_KIND_MULTICAST
    if first & 0x02:
        return MAC_KIND_LOCAL
    return MAC_KIND_UNIVERSAL

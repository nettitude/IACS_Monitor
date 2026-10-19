"""
Purdue / ISA-99 (IEC 62443) level vocabulary - the ONE source of truth (F-08).

Levels, lowest (most trusted, closest to the process) to highest::

    0    Physical process         sensors, actuators, field instruments
    1    Basic control            PLC, RTU, IED, DCS controllers
    2    Supervisory control      HMI, local / area SCADA, alarm systems
    3    Site operations          historians, MES, engineering workstations
    3.5  Industrial DMZ           jump hosts, historian replicas, patch / AV relays
    4    Enterprise / business    ERP, corporate IT
    5    Internet / external      enterprise edge, WAN, internet

Representation
--------------
Whole levels are plain ``int``; the industrial DMZ is the ``float`` 3.5
(``3.5 == 7 / 2`` is exact in binary floating point, and 3 == 3.0 hash
identically, so sets / dict keys mix safely).  ``normalize_level`` is the
only parser: every value that enters the system (API input, CSV import,
DB read via ``app.models.PurdueLevelType``) goes through it, so the rest of
the code only ever sees ``0, 1, 2, 3, 3.5, 4, 5`` and JSON serialises
``3`` (not ``3.0``) and ``3.5``.

Ordering and adjacency
----------------------
Levels are ordered numerically.  Adjacency is defined on the *ordered list*
(``level_distance``), not on arithmetic difference: L3<->L3.5 and
L3.5<->L4 are adjacent (distance 1) and L3<->L4 is distance 2 - it skips
the DMZ.  ``next_level`` / ``prev_level`` step along the same list.

Semantic predicates (how checks classify a level)
--------------------------------------------------
``is_ot``        L0-L2           control / field zones
``is_deep_ot``   L0-L1           field devices and basic control
``is_site_ops``  L3              site operations (still OT-owned)
``is_dmz``       L3.5            industrial DMZ
``is_it``        L4-L5           enterprise / internet
``is_it_side``   L3 and above    "above the control zones".  The legacy
                                 ``level >= 3`` tests in alert_engine
                                 (it_ot_bypass, rule_it_to_ot, insecure
                                 IT->OT, inter-VLAN IT/OT crossing,
                                 disabled-rule IT->OT, mgmt-from-wrong-zone
                                 twins) keep this meaning: L3 was always
                                 grouped with IT on the far side of the
                                 L2/L3 conduit, and the DMZ, sitting above
                                 L3, falls on the same side.  A DMZ host
                                 reaching L1 directly is still a bypass.

Where the DMZ is treated differently from L4/L5 (documented at each site
in alert_engine): management / remote access from the DMZ into L0-L2 is
the sanctioned ISA/IEC 62443 remote-access pattern (operator -> enterprise
-> DMZ jump host -> OT), so those findings are reported one severity step
lower than the same access from L3 / L4 / L5, with ``dmz_source`` in the
evidence - they still fire, because the jump host should be inventoried
and the rule scoped to it.
"""
from __future__ import annotations

import math
import re
from typing import Iterable, Iterator, Optional, Union

Level = Union[int, float]

DMZ_LEVEL: float = 3.5

#: Every valid Purdue level, in order (lowest = most trusted).
VALID_LEVELS: tuple = (0, 1, 2, 3, DMZ_LEVEL, 4, 5)

PURDUE_LEVEL_MIN = VALID_LEVELS[0]
PURDUE_LEVEL_MAX = VALID_LEVELS[-1]

#: Human-readable names (match the UI's LEVEL_DESC).
LEVEL_NAMES: dict = {
    0: "Physical Process",
    1: "Basic Control",
    2: "Supervisory Control",
    3: "Site Operations",
    DMZ_LEVEL: "Industrial DMZ",
    4: "Business / Enterprise",
    5: "Internet / External",
}

#: Text used in validation messages (kept containing "0–5" for continuity).
VALID_LEVELS_TEXT = "0, 1, 2, 3, 3.5 (Industrial DMZ), 4, 5"
PURDUE_LEVEL_RANGE_TEXT = f"0–5: one of {VALID_LEVELS_TEXT}"

def check_sql(column: str) -> str:
    """SQL CHECK body for a Purdue level column (NULL allowed).  Mirrored
    verbatim in alembic revision b9c0d1e2f3a4 (migrations never import app)."""
    return f"{column} IS NULL OR {column} IN (0, 1, 2, 3, 3.5, 4, 5)"


_INDEX = {lv: i for i, lv in enumerate(VALID_LEVELS)}
_ALIASES = {"dmz": DMZ_LEVEL, "idmz": DMZ_LEVEL, "industrial dmz": DMZ_LEVEL,
            "industrial_dmz": DMZ_LEVEL, "l3.5": DMZ_LEVEL, "level 3.5": DMZ_LEVEL}
_STR_RE = re.compile(r"^(?:l|level)?\s*([0-9]+(?:\.[0-9]+)?)$")


def _canon(num: float) -> Optional[Level]:
    """Canonical value for a numeric level, or None when not valid."""
    if not math.isfinite(num):
        return None
    if num == DMZ_LEVEL:
        return DMZ_LEVEL
    if num == int(num) and int(num) in _INDEX:
        return int(num)
    return None


def normalize_level(value) -> Optional[Level]:
    """Parse a Purdue level.

    Accepts ``int`` / ``float`` / ``Decimal`` / numeric strings ("3",
    "3.0", "3.5"), "L3" / "L3.5" / "Level 3", and "dmz" / "idmz".  Returns
    an ``int`` for whole levels, ``3.5`` for the DMZ, ``None`` for ``None``
    (and for an empty / whitespace string).  Raises ``ValueError`` for
    anything else, including ``bool``.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"not a Purdue level: {value!r}")
    if isinstance(value, str):
        s = value.strip().lower()
        if not s:
            return None
        if s in _ALIASES:
            return _ALIASES[s]
        m = _STR_RE.match(s)
        if not m:
            raise ValueError(f"not a Purdue level: {value!r}")
        num = float(m.group(1))
    else:
        try:
            num = float(value)
        except (TypeError, ValueError):
            raise ValueError(f"not a Purdue level: {value!r}") from None
    lv = _canon(num)
    if lv is None:
        raise ValueError(f"not a Purdue level: {value!r}")
    return lv


def is_valid_level(value) -> bool:
    """True when ``value`` is a (non-bool) number equal to a valid level.

    Strings are NOT accepted here - parse them with ``normalize_level``.
    """
    if isinstance(value, bool) or isinstance(value, str) or value is None:
        return False
    try:
        return _canon(float(value)) is not None
    except (TypeError, ValueError):
        return False


def purdue_level_error(field: str, value) -> str:
    """Uniform validation message for an invalid level (API 422s)."""
    return f"{field} must be a Purdue level {PURDUE_LEVEL_RANGE_TEXT}; got {value!r}"


def fmt_level(value, prefix: str = "L", unknown: str = "?") -> str:
    """``3`` -> "L3", ``3.5`` -> "L3.5", None / invalid -> ``prefix + unknown``."""
    try:
        lv = normalize_level(value)
    except ValueError:
        lv = None
    if lv is None:
        return f"{prefix}{unknown}"
    return f"{prefix}{lv}"


def level_label(value) -> str:
    """"L3.5 Industrial DMZ" style label; "Unclassified" for None."""
    try:
        lv = normalize_level(value)
    except ValueError:
        lv = None
    if lv is None:
        return "Unclassified"
    return f"{fmt_level(lv)} {LEVEL_NAMES[lv]}"


def sorted_levels(levels: Iterable, *, reverse: bool = False) -> list:
    """Valid levels from ``levels``, normalised, de-duplicated and sorted."""
    out = set()
    for lv in levels:
        try:
            n = normalize_level(lv)
        except ValueError:
            continue
        if n is not None:
            out.add(n)
    return sorted(out, reverse=reverse)


def iter_levels(*, reverse: bool = False) -> Iterator[Level]:
    """Every valid level, lowest first (or highest first with reverse)."""
    return iter(VALID_LEVELS[::-1] if reverse else VALID_LEVELS)


def canonical_levels() -> list:
    """[{"level", "label", "name"}] for every level (GET /purdue-levels)."""
    return [{"level": lv, "label": fmt_level(lv), "name": LEVEL_NAMES[lv],
             "is_dmz": lv == DMZ_LEVEL} for lv in VALID_LEVELS]


# ---------------------------------------------------------------- ordering --

def level_index(value) -> int:
    """Position of a level in VALID_LEVELS (raises ValueError if invalid)."""
    lv = normalize_level(value)
    if lv is None:
        raise ValueError("level is None")
    return _INDEX[lv]


def level_distance(a, b) -> int:
    """Number of Purdue steps between two levels (3<->3.5 = 1, 3<->4 = 2)."""
    return abs(level_index(a) - level_index(b))


def is_adjacent(a, b) -> bool:
    return level_distance(a, b) == 1


def next_level(value) -> Level:
    """The next less-trusted level (clamped at L5)."""
    return VALID_LEVELS[min(level_index(value) + 1, len(VALID_LEVELS) - 1)]


def prev_level(value) -> Level:
    """The next more-trusted level (clamped at L0)."""
    return VALID_LEVELS[max(level_index(value) - 1, 0)]


def levels_between(a, b) -> list:
    """Levels strictly between ``a`` and ``b`` (e.g. 3, 4 -> [3.5])."""
    i, j = sorted((level_index(a), level_index(b)))
    return list(VALID_LEVELS[i + 1:j])


# -------------------------------------------------------------- predicates --
# All predicates return False for None.

def is_ot(value) -> bool:
    """L0-L2: control and field zones."""
    return value is not None and value <= 2


def is_deep_ot(value) -> bool:
    """L0-L1: field devices and basic control."""
    return value is not None and value <= 1


def is_site_ops(value) -> bool:
    """L3: site operations."""
    return value is not None and value == 3


def is_dmz(value) -> bool:
    """L3.5: industrial DMZ."""
    return value is not None and value == DMZ_LEVEL


def is_it(value) -> bool:
    """L4-L5: enterprise / internet."""
    return value is not None and value >= 4


def is_it_side(value) -> bool:
    """L3 and above (L3, L3.5, L4, L5): the far side of the L2/L3 conduit,
    as the legacy ``>= 3`` IT checks define it (see module docstring)."""
    return value is not None and value >= 3

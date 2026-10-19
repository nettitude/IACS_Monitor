"""ISA/IEC 62443-3-3 foundational requirements (FR) and security levels (SL).

Every finding and check carries an ``isa62443_sr`` string such as
``"SR 5.1 RE2, SR 5.2"``.  This module derives from that string:

* the FRs the requirements belong to (SR 5.x -> FR5 "Restricted data flow");
* the security level at which each requirement first applies (the SL-C
  column of 62443-3-3 Annex B: a base SR or a requirement enhancement (RE)
  marked for SL 1 applies at SL 1-4, one first marked for SL 3 at SL 3-4);
* the check's level: the LOWEST level among its requirements, i.e. the
  lowest target security level (SL-T) at which the finding is in scope.

A finding whose string has no 62443-3-3 requirement (only 62443-2-1 or
62443-3-2 references such as "2-1 SPE 2" or "ZCR 3") has no FR and no level:
it is a programme / risk-assessment item that applies at every target level,
so a target-level filter always keeps it.

Verify the table against the licensed standard before relying on it in an
assessment.
"""
from __future__ import annotations

import re
from functools import lru_cache
from typing import Iterable, Optional

FR_NAMES: dict[str, str] = {
    "FR1": "Identification and authentication control",
    "FR2": "Use control",
    "FR3": "System integrity",
    "FR4": "Data confidentiality",
    "FR5": "Restricted data flow",
    "FR6": "Timely response to events",
    "FR7": "Resource availability",
}
FR_SHORT: dict[str, str] = {
    "FR1": "IAC", "FR2": "UC", "FR3": "SI", "FR4": "DC",
    "FR5": "RDF", "FR6": "TRE", "FR7": "RA",
}
SECURITY_LEVELS = (1, 2, 3, 4)

# (SR, RE) -> lowest SL at which it applies.  RE 0 = the base requirement.
# IEC 62443-3-3:2013 Annex B (SL-C(FR, control system) mapping).
_SL_TABLE: dict[tuple[str, int], int] = {
    # FR1 Identification and authentication control
    ("1.1", 0): 1, ("1.1", 1): 2, ("1.1", 2): 3, ("1.1", 3): 4,
    ("1.2", 0): 2, ("1.2", 1): 3,
    ("1.3", 0): 1, ("1.3", 1): 3,
    ("1.4", 0): 1,
    ("1.5", 0): 1, ("1.5", 1): 3,
    ("1.6", 0): 1, ("1.6", 1): 3,
    ("1.7", 0): 1, ("1.7", 1): 3,
    ("1.8", 0): 2,
    ("1.9", 0): 2, ("1.9", 1): 4,
    ("1.10", 0): 1,
    ("1.11", 0): 1,
    ("1.12", 0): 1,
    ("1.13", 0): 1, ("1.13", 1): 2,
    ("1.14", 0): 2, ("1.14", 1): 4,
    # FR2 Use control
    ("2.1", 0): 1, ("2.1", 1): 2, ("2.1", 2): 2, ("2.1", 3): 3, ("2.1", 4): 4,
    ("2.2", 0): 1,
    ("2.3", 0): 1, ("2.3", 1): 2,
    ("2.4", 0): 1, ("2.4", 1): 3,
    ("2.5", 0): 2,
    ("2.6", 0): 2,
    ("2.7", 0): 3,
    ("2.8", 0): 1, ("2.8", 1): 3,
    ("2.9", 0): 1, ("2.9", 1): 3,
    ("2.10", 0): 1,
    ("2.11", 0): 1, ("2.11", 1): 3, ("2.11", 2): 4,
    ("2.12", 0): 3, ("2.12", 1): 4,
    # FR3 System integrity
    ("3.1", 0): 1, ("3.1", 1): 3,
    ("3.2", 0): 1, ("3.2", 1): 2, ("3.2", 2): 3,
    ("3.3", 0): 1, ("3.3", 1): 3, ("3.3", 2): 4,
    ("3.4", 0): 2, ("3.4", 1): 3, ("3.4", 2): 4,
    ("3.5", 0): 1,
    ("3.6", 0): 1,
    ("3.7", 0): 1,
    ("3.8", 0): 2, ("3.8", 1): 3, ("3.8", 2): 4, ("3.8", 3): 3,
    ("3.9", 0): 2, ("3.9", 1): 4,
    # FR4 Data confidentiality
    ("4.1", 0): 1, ("4.1", 1): 3, ("4.1", 2): 4,
    ("4.2", 0): 2, ("4.2", 1): 3,
    ("4.3", 0): 1,
    # FR5 Restricted data flow
    ("5.1", 0): 1, ("5.1", 1): 2, ("5.1", 2): 3, ("5.1", 3): 3,
    ("5.2", 0): 1, ("5.2", 1): 2, ("5.2", 2): 3, ("5.2", 3): 3,
    ("5.3", 0): 1, ("5.3", 1): 3,
    ("5.4", 0): 1,
    # FR6 Timely response to events
    ("6.1", 0): 1, ("6.1", 1): 3,
    ("6.2", 0): 2,
    # FR7 Resource availability
    ("7.1", 0): 1, ("7.1", 1): 2, ("7.1", 2): 3,
    ("7.2", 0): 1,
    ("7.3", 0): 1, ("7.3", 1): 2, ("7.3", 2): 4,
    ("7.4", 0): 1,
    ("7.5", 0): 1,
    ("7.6", 0): 1, ("7.6", 1): 3,
    ("7.7", 0): 1,
    ("7.8", 0): 2,
}

# "SR 5.1 RE2", "SR 5.1 RE 2", "SR5.1(2)", or a bare "5.2" continuing an SR list.
_SR_RE = re.compile(r"^(?:SR\s*)?(\d)\.(\d{1,2})(?:\s*(?:\(?\s*RE\s*(\d)\s*\)?|\((\d)\)))?$", re.I)


def _label(sr: str, re_no: int) -> str:
    return f"SR {sr}" + (f" RE{re_no}" if re_no else "")


@lru_cache(maxsize=4096)
def parse(sr_text: Optional[str]) -> tuple[tuple[str, str, Optional[int]], ...]:
    """62443-3-3 requirements in ``sr_text``: ((label, FR, SL), ...) in order.

    Non-3-3 parts ("ZCR 3", "2-1 NET 1.4", free text) are ignored; a bare
    number only counts when the text names an SR first ("SR 2.9, 2.10")."""
    if not sr_text:
        return ()
    out: list[tuple[str, str, Optional[int]]] = []
    seen_sr = False
    for raw in re.split(r"[,/;]| and ", str(sr_text)):
        tok = raw.strip().rstrip(".")
        if not tok:
            continue
        # cut trailing prose ("SR 7.4 — HA failover ...")
        tok = re.split(r"\s+[—–-]\s+", tok, maxsplit=1)[0].strip()
        m = _SR_RE.match(tok)
        if not m:
            continue
        named = tok.upper().startswith("SR")
        if not named and not seen_sr:
            continue
        seen_sr = True
        fr_no, sub = m.group(1), m.group(2)
        if fr_no not in "1234567":
            continue
        sr = f"{fr_no}.{int(sub)}"
        re_no = int(m.group(3) or m.group(4) or 0)
        sl = _SL_TABLE.get((sr, re_no))
        if sl is None and (sr, 0) not in _SL_TABLE:
            continue                          # not a 62443-3-3 SR (e.g. "SR 8.1")
        label = _label(sr, re_no)
        if any(o[0] == label for o in out):
            continue
        out.append((label, f"FR{fr_no}", sl))
    return tuple(out)


def frs(sr_text: Optional[str]) -> list[str]:
    """Distinct FRs of ``sr_text`` in first-mentioned order (["FR5", "FR1"])."""
    seen: list[str] = []
    for _, fr, _ in parse(sr_text):
        if fr not in seen:
            seen.append(fr)
    return seen


def security_level(sr_text: Optional[str]) -> Optional[int]:
    """Lowest SL at which any requirement of ``sr_text`` applies; None when
    the text has no 62443-3-3 requirement (applies at every level)."""
    levels = [sl for _, _, sl in parse(sr_text) if sl is not None]
    return min(levels) if levels else None


def sl_by_requirement(sr_text: Optional[str]) -> dict[str, Optional[int]]:
    """{"SR 5.1 RE2": 3, "SR 5.2": 1} for ``sr_text``."""
    return {label: sl for label, _, sl in parse(sr_text)}


def describe(sr_text: Optional[str]) -> dict:
    """{fr: [...], sl: int|None, sl_by_sr: {...}} for API rows / the catalogue."""
    return {"fr": frs(sr_text), "sl": security_level(sr_text),
            "sl_by_sr": sl_by_requirement(sr_text)}


def matches(sr_text: Optional[str], target_sl: Optional[int] = None,
            fr: Optional[str] = None) -> bool:
    """Is a finding with ``sr_text`` in scope for target level ``target_sl``
    (its level <= target, or it has no 3-3 level) and foundational
    requirement ``fr`` (any of its requirements is in that FR)?"""
    if fr is not None and fr not in frs(sr_text):
        return False
    if target_sl is not None:
        sl = security_level(sr_text)
        if sl is not None and sl > target_sl:
            return False
    return True


def matching_values(values: Iterable[Optional[str]], target_sl: Optional[int] = None,
                    fr: Optional[str] = None) -> tuple[list[str], bool]:
    """Split distinct SR strings for a SQL ``IN`` filter: (matching non-null
    values, whether NULL/empty SR rows match too)."""
    keep = [v for v in values if v and matches(v, target_sl, fr)]
    return keep, matches(None, target_sl, fr)


def normalize_fr(value: Optional[str]) -> Optional[str]:
    """"FR5", "fr5", "5", "RDF" -> "FR5"; None/"" -> None; ValueError otherwise."""
    if value is None or not str(value).strip():
        return None
    v = str(value).strip().upper()
    if v.isdigit():
        v = "FR" + v
    for k, short in FR_SHORT.items():
        if v == short:
            v = k
    if v not in FR_NAMES:
        raise ValueError(f"unknown foundational requirement {value!r} (FR1-FR7)")
    return v


def normalize_sl(value) -> Optional[int]:
    """Target level filter: 0-4, "SL2", "SL-T 2", "SL0 - No Requirements" -> int;
    None/"" -> None; ValueError otherwise.  SL0 (owner 2026-10-14: the report's
    SL-T list matches the other SL lists) keeps only findings with no 62443-3-3
    requirement - every 3-3 requirement applies from SL1 up."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    try:
        return parse_level_value(value)
    except ValueError:
        raise ValueError(f"target security level must be 0-4, got {value!r}")


# ------------------------------------------------ security level values --
# IEC 62443 security levels as recorded values (SL-T / SL-A / SL-C) - owner
# 2026-10-13: SL0 is a real level ("no requirements"), distinct from "not set".
# Shared by the zone documentation (app.iec_zones) and the inventory imports
# (parsers must not import the zone module).
import re as _re

SL_LABELS = {0: "SL0 - No Requirements", 1: "SL1 - Casual/Accidents", 2: "SL2 - Simple Intentional Means",
             3: "SL3 - Sophisticated Attacks", 4: "SL4 - Advanced Resources"}
_SL_VALUE_RE = _re.compile(r"^\s*(?:SL\s*-?\s*[TCA]?\s*)?([0-4])(?:\s*(?:-|:|\u2013)\s*.*)?\s*$", _re.I)
SL_VALUE_ERROR = "security level must be 0, 1, 2, 3 or 4 (SL0-SL4)"


def parse_level_value(v) -> int:
    """'3', 3, 'SL3', 'SL-C 3', 'SL-T 3', 'SL2 - Simple Intentional Means' -> the
    level 0-4; ValueError otherwise."""
    if isinstance(v, bool):
        raise ValueError(SL_VALUE_ERROR)
    if isinstance(v, int):
        n = v
    else:
        m = _SL_VALUE_RE.match(str(v))
        if not m:
            raise ValueError(SL_VALUE_ERROR)
        n = int(m.group(1))
    if n not in SL_LABELS:
        raise ValueError(SL_VALUE_ERROR)
    return n

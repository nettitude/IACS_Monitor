"""
Tests for parse_address_spec() and parse_port_spec() in
app/parsers/topology_diff.py — pure functions, no DB needed.
"""
import ipaddress

import pytest

from app.parsers.topology_diff import parse_address_spec, parse_port_spec


# ──────────────────────────────────────────────── parse_address_spec ─────────


def test_any_returns_string_any():
    assert parse_address_spec("any") == "any"


def test_cidr_returns_network():
    result = parse_address_spec("10.0.0.0/24")
    assert result == ipaddress.IPv4Network("10.0.0.0/24")


def test_host_prefix_returns_slash32():
    result = parse_address_spec("host 10.0.0.1")
    assert result == ipaddress.IPv4Network("10.0.0.1/32")


def test_bare_ip_returns_slash32():
    result = parse_address_spec("10.0.0.1")
    assert result == ipaddress.IPv4Network("10.0.0.1/32")


def test_cisco_wildcard_mask():
    result = parse_address_spec("10.0.1.0 0.0.0.255")
    assert result == ipaddress.IPv4Network("10.0.1.0/24")


def test_network_alias_returns_none():
    assert parse_address_spec("network:lan") is None


def test_empty_returns_none():
    assert parse_address_spec(None) is None


def test_invalid_returns_none():
    assert parse_address_spec("not_an_ip") is None


# ──────────────────────────────────────────────── parse_port_spec ────────────


def test_port_none_returns_any():
    assert parse_port_spec(None) == "any"


def test_port_any_returns_any():
    assert parse_port_spec("any") == "any"


def test_port_single_number():
    assert parse_port_spec("80") == {80}


def test_port_eq_format():
    assert parse_port_spec("eq 443") == {443}


def test_port_range():
    result = parse_port_spec("80-90")
    assert isinstance(result, set)
    assert len(result) == 11
    assert result == set(range(80, 91))


def test_port_gt():
    result = parse_port_spec("gt 1023")
    assert isinstance(result, set)
    assert len(result) == 64512
    assert 1024 in result
    assert 65535 in result
    assert 1023 not in result


def test_port_lt():
    result = parse_port_spec("lt 1024")
    assert isinstance(result, set)
    assert len(result) == 1024
    assert 0 in result
    assert 1023 in result
    assert 1024 not in result


def test_port_unresolvable_named_object():
    # "HTTPS" is a PAN-OS service name — not a recognizable numeric format
    assert parse_port_spec("HTTPS") is None

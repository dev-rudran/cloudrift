"""CIDR helpers built on the standard library ``ipaddress`` module."""

from __future__ import annotations

import ipaddress

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_network(value: object) -> Network | None:
    """Parse a CIDR string, or an address (treated as a host network)."""

    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def cidr_contains(container: object, candidate: object) -> bool:
    """Return True when ``candidate`` is inside ``container``.

    Both arguments may be CIDRs or bare addresses. Mixed address families and
    unparsable values return False instead of raising.
    """

    outer = parse_network(container)
    inner = parse_network(candidate)
    if outer is None or inner is None:
        return False
    if outer.version != inner.version:
        return False
    return inner.subnet_of(outer)


def is_public_cidr(value: object) -> bool:
    """Return True for ranges that expose resources to the public internet.

    This is true for ``0.0.0.0/0`` and ``::/0`` as well as any range that is
    wholly globally routable. Private, loopback, link-local, multicast,
    documentation, and otherwise reserved ranges return False.
    """

    network = parse_network(value)
    if network is None:
        return False
    if network.prefixlen == 0:
        return True
    if network.version == 4:
        if (
            network.is_private
            or network.is_loopback
            or network.is_link_local
            or network.is_multicast
            or network.is_reserved
            or network.is_unspecified
        ):
            return False
        return network.is_global
    if (
        network.is_private
        or network.is_loopback
        or network.is_link_local
        or network.is_multicast
        or network.is_reserved
        or network.is_unspecified
    ):
        return False
    return network.is_global

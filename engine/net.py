"""Small network helpers shared by the rules."""
from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import Any

# RFC 1918 private ranges (plus IPv6 unique-local). In the lab data the
# documentation ranges 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 play
# the role of the Internet, so they must NOT count as internal - Python's own
# ``ip_address(x).is_private`` would say they are.
INTERNAL_NETWORKS = tuple(ip_network(net) for net in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
))


def is_internal(ip: Any, networks=INTERNAL_NETWORKS) -> bool:
    """True when ``ip`` is a valid address inside one of the internal networks."""
    if not ip:
        return False
    try:
        address = ip_address(str(ip))
    except ValueError:
        return False
    return any(address in network for network in networks)

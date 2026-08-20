"""The unit of traffic the engine makes decisions about.

A :class:`Packet` is a normalised description of one network event: who sent
it, who it was addressed to, over which protocol, and in which direction
relative to the host running the firewall.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any

from firewall.errors import PacketError

IPAddress = IPv4Address | IPv6Address

#: Protocols a packet may carry. ICMP packets have no ports.
PROTOCOLS = ("TCP", "UDP", "ICMP")

#: Direction relative to the protected host: inbound or outbound.
DIRECTIONS = ("IN", "OUT")

MIN_PORT = 0
MAX_PORT = 65535

_FIELDS = ("src_ip", "dst_ip", "protocol", "direction", "src_port", "dst_port")
_REQUIRED = ("src_ip", "dst_ip", "protocol", "direction")


@dataclass(frozen=True)
class Packet:
    """One network event, with its fields validated on construction.

    IP addresses may be passed as strings; they are parsed into
    :mod:`ipaddress` objects so that IPv4 and IPv6 compare correctly against
    rule networks. Ports are optional because ICMP has none.
    """

    src_ip: IPAddress
    dst_ip: IPAddress
    protocol: str
    direction: str
    src_port: int | None = None
    dst_port: int | None = None

    def __post_init__(self) -> None:
        # frozen=True blocks normal assignment, so normalised values are
        # written back through object.__setattr__.
        object.__setattr__(self, "src_ip", _parse_ip(self.src_ip, "src_ip"))
        object.__setattr__(self, "dst_ip", _parse_ip(self.dst_ip, "dst_ip"))
        object.__setattr__(self, "protocol", _parse_choice(self.protocol, PROTOCOLS, "protocol"))
        object.__setattr__(
            self, "direction", _parse_choice(self.direction, DIRECTIONS, "direction")
        )
        object.__setattr__(self, "src_port", _parse_port(self.src_port, "src_port"))
        object.__setattr__(self, "dst_port", _parse_port(self.dst_port, "dst_port"))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Packet:
        """Build a packet from a plain dict, e.g. one decoded from JSON."""
        if not isinstance(data, dict):
            raise PacketError(f"packet must be an object, got {type(data).__name__}")

        unknown = sorted(set(data) - set(_FIELDS))
        if unknown:
            raise PacketError(
                f"unknown packet field(s): {', '.join(unknown)}. "
                f"Valid fields are: {', '.join(_FIELDS)}"
            )

        missing = [field for field in _REQUIRED if data.get(field) is None]
        if missing:
            raise PacketError(f"packet is missing required field(s): {', '.join(missing)}")

        return cls(**data)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict, the inverse of :meth:`from_dict`."""
        return {
            "src_ip": str(self.src_ip),
            "dst_ip": str(self.dst_ip),
            "protocol": self.protocol,
            "direction": self.direction,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
        }

    def __str__(self) -> str:
        src = _endpoint(self.src_ip, self.src_port)
        dst = _endpoint(self.dst_ip, self.dst_port)
        return f"{self.direction} {self.protocol} {src} -> {dst}"


def _endpoint(ip: IPAddress, port: int | None) -> str:
    """Format an address/port pair, bracketing IPv6 as in RFC 3986."""
    host = f"[{ip}]" if isinstance(ip, IPv6Address) else str(ip)
    return host if port is None else f"{host}:{port}"


def _parse_ip(value: Any, field: str) -> IPAddress:
    if isinstance(value, (IPv4Address, IPv6Address)):
        return value
    # ip_address() accepts a bare int as a packed address, so 42 would quietly
    # become 0.0.0.42. In a packet description that is always a mistake.
    if not isinstance(value, str):
        raise PacketError(f"{field}: expected an IP address string, got {value!r}")
    try:
        return ip_address(value.strip())
    except ValueError as exc:
        raise PacketError(f"{field}: {value!r} is not a valid IP address") from exc


def _parse_choice(value: Any, allowed: tuple, field: str) -> str:
    if not isinstance(value, str):
        raise PacketError(f"{field}: expected a string, got {type(value).__name__}")
    normalised = value.strip().upper()
    if normalised not in allowed:
        raise PacketError(f"{field}: {value!r} is not one of {', '.join(allowed)}")
    return normalised


def _parse_port(value: Any, field: str) -> int | None:
    if value is None:
        return None
    # bool is a subclass of int, and True would silently become port 1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise PacketError(f"{field}: expected an integer port, got {value!r}")
    if not MIN_PORT <= value <= MAX_PORT:
        raise PacketError(f"{field}: port {value} is outside {MIN_PORT}-{MAX_PORT}")
    return value

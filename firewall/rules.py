"""Rule definitions and the JSON rule file loader.

A rule is a *pattern* plus an *action*. The engine walks the rules in order and
the first one whose pattern matches the packet decides its fate, so the order
of rules in the file is significant.

Any field left out of a rule means "match anything", which makes a rule with no
patterns at all a catch-all.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network, ip_network
from pathlib import Path
from typing import Any

from firewall.errors import RuleError
from firewall.packets import MAX_PORT, MIN_PORT, PROTOCOLS, Packet

IPNetwork = IPv4Network | IPv6Network

#: What a rule does with a packet it matches.
ACTIONS = ("ALLOW", "DENY")

#: Wildcard accepted by the ``protocol`` and ``direction`` fields.
ANY = "ANY"

RULE_PROTOCOLS = PROTOCOLS + (ANY,)
RULE_DIRECTIONS = ("IN", "OUT", ANY)

_FIELDS = (
    "name",
    "action",
    "src_cidr",
    "dst_cidr",
    "src_port",
    "dst_port",
    "protocol",
    "direction",
    "enabled",
    "description",
)


@dataclass(frozen=True)
class PortSpec:
    """A set of ports, stored as inclusive ``(low, high)`` ranges.

    Accepts a single port (``80``), a range (``"8000-8100"``), a comma
    separated list (``"80,443"``), or a JSON list mixing those forms.
    """

    ranges: tuple[tuple[int, int], ...]

    @classmethod
    def parse(cls, value: Any, field_name: str) -> PortSpec | None:
        """Parse a port specification, or return ``None`` for "any port"."""
        if value is None:
            return None

        parts: Sequence[Any]
        if isinstance(value, (list, tuple)):
            parts = value
        elif isinstance(value, str):
            parts = [chunk for chunk in value.split(",") if chunk.strip()]
        else:
            parts = [value]

        if not parts:
            raise RuleError(f"{field_name}: port specification is empty")

        ranges = tuple(cls._parse_part(part, field_name) for part in parts)
        return cls(ranges=ranges)

    @staticmethod
    def _parse_part(part: Any, field_name: str) -> tuple[int, int]:
        if isinstance(part, bool):
            raise RuleError(f"{field_name}: {part!r} is not a valid port")
        if isinstance(part, int):
            port = _check_port(part, field_name)
            return (port, port)
        if not isinstance(part, str):
            raise RuleError(f"{field_name}: {part!r} is not a valid port")

        text = part.strip()
        if "-" not in text:
            port = _check_port(_to_int(text, field_name), field_name)
            return (port, port)

        low_text, _, high_text = text.partition("-")
        if not low_text.strip() or not high_text.strip():
            raise RuleError(
                f"{field_name}: {text!r} is not a valid port range; "
                f"write it as 'low-high', e.g. '8000-8100'"
            )
        low = _check_port(_to_int(low_text, field_name), field_name)
        high = _check_port(_to_int(high_text, field_name), field_name)
        if low > high:
            raise RuleError(f"{field_name}: range {text!r} starts above where it ends")
        return (low, high)

    def contains(self, port: int | None) -> bool:
        """Return whether ``port`` falls in this spec. A portless packet never does."""
        if port is None:
            return False
        return any(low <= port <= high for low, high in self.ranges)

    def __str__(self) -> str:
        return ",".join(str(low) if low == high else f"{low}-{high}" for low, high in self.ranges)


@dataclass(frozen=True)
class Rule:
    """One ordered firewall rule.

    ``src_cidr``/``dst_cidr`` hold parsed networks; an empty tuple matches every
    address, of either IP family. :meth:`from_dict` accepts a single CIDR string
    or a list of them for those fields.
    """

    name: str
    action: str
    src_cidr: tuple[IPNetwork, ...] = ()
    dst_cidr: tuple[IPNetwork, ...] = ()
    src_port: PortSpec | None = None
    dst_port: PortSpec | None = None
    protocol: str = ANY
    direction: str = ANY
    enabled: bool = True
    description: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any], where: str = "rule") -> Rule:
        """Build a rule from its JSON form, reporting problems against ``where``."""
        if not isinstance(data, dict):
            raise RuleError(f"{where}: expected an object, got {type(data).__name__}")

        unknown = sorted(set(data) - set(_FIELDS))
        if unknown:
            raise RuleError(
                f"{where}: unknown field(s): {', '.join(unknown)}. "
                f"Valid fields are: {', '.join(_FIELDS)}"
            )

        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            raise RuleError(f"{where}: 'name' is required and must be a non-empty string")
        name = name.strip()
        # Keep the caller's context (file and position) and add the name, so an
        # error points at both where the rule lives and which one it is.
        where = f"{where} {name!r}"

        action = _parse_choice(data.get("action"), ACTIONS, "action", where, required=True)

        enabled = data.get("enabled", True)
        if not isinstance(enabled, bool):
            raise RuleError(f"{where}: 'enabled' must be true or false, got {enabled!r}")

        description = data.get("description", "")
        if not isinstance(description, str):
            raise RuleError(f"{where}: 'description' must be a string")

        return cls(
            name=name,
            action=action,
            src_cidr=_parse_networks(data.get("src_cidr"), "src_cidr", where),
            dst_cidr=_parse_networks(data.get("dst_cidr"), "dst_cidr", where),
            src_port=PortSpec.parse(data.get("src_port"), f"{where}: src_port"),
            dst_port=PortSpec.parse(data.get("dst_port"), f"{where}: dst_port"),
            protocol=_parse_choice(data.get("protocol"), RULE_PROTOCOLS, "protocol", where),
            direction=_parse_choice(data.get("direction"), RULE_DIRECTIONS, "direction", where),
            enabled=enabled,
            description=description.strip(),
        )

    def matches(self, packet: Packet) -> bool:
        """Return whether ``packet`` satisfies every pattern on this rule."""
        if not self.enabled:
            return False
        if self.protocol != ANY and packet.protocol != self.protocol:
            return False
        if self.direction != ANY and packet.direction != self.direction:
            return False
        if not _in_networks(packet.src_ip, self.src_cidr):
            return False
        if not _in_networks(packet.dst_ip, self.dst_cidr):
            return False
        if self.src_port is not None and not self.src_port.contains(packet.src_port):
            return False
        return not (self.dst_port is not None and not self.dst_port.contains(packet.dst_port))

    def __str__(self) -> str:
        parts = [f"{self.action:<5} {self.name}"]
        if self.direction != ANY:
            parts.append(f"direction={self.direction}")
        if self.protocol != ANY:
            parts.append(f"protocol={self.protocol}")
        if self.src_cidr:
            parts.append("src=" + ",".join(str(net) for net in self.src_cidr))
        if self.dst_cidr:
            parts.append("dst=" + ",".join(str(net) for net in self.dst_cidr))
        if self.src_port is not None:
            parts.append(f"sport={self.src_port}")
        if self.dst_port is not None:
            parts.append(f"dport={self.dst_port}")
        if not self.enabled:
            parts.append("(disabled)")
        return "  ".join(parts)


def load_rules(path: str | Path) -> list[Rule]:
    """Read and validate a JSON rule file, returning rules in file order."""
    rule_path = Path(path)
    try:
        text = rule_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuleError(f"cannot read rule file {rule_path}: {exc}") from exc

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuleError(f"{rule_path} is not valid JSON: {exc}") from exc

    return parse_rules(data, source=str(rule_path))


def parse_rules(data: Any, source: str = "rules") -> list[Rule]:
    """Validate an already-decoded rule document."""
    if isinstance(data, dict):
        if "rules" not in data:
            raise RuleError(f"{source}: object has no 'rules' key")
        entries = data["rules"]
    else:
        entries = data

    if not isinstance(entries, list):
        raise RuleError(f"{source}: 'rules' must be a list, got {type(entries).__name__}")

    return [
        Rule.from_dict(entry, where=f"{source}: rule #{index + 1}")
        for index, entry in enumerate(entries)
    ]


def _parse_networks(value: Any, field_name: str, where: str) -> tuple[IPNetwork, ...]:
    if value is None:
        return ()
    items: Iterable[Any] = value if isinstance(value, (list, tuple)) else [value]

    networks = []
    for item in items:
        if not isinstance(item, str):
            raise RuleError(f"{where}: {field_name} expects CIDR strings, got {item!r}")
        try:
            # strict=False lets "192.168.1.5/24" mean the /24 it sits in.
            networks.append(ip_network(item.strip(), strict=False))
        except ValueError as exc:
            raise RuleError(f"{where}: {field_name} {item!r} is not a valid CIDR: {exc}") from exc
    return tuple(networks)


def _in_networks(ip: Any, networks: tuple[IPNetwork, ...]) -> bool:
    if not networks:
        return True
    # Comparing an IPv4 address against an IPv6 network raises TypeError, so
    # the families are checked before the membership test.
    return any(net.version == ip.version and ip in net for net in networks)


def _parse_choice(
    value: Any,
    allowed: tuple,
    field_name: str,
    where: str,
    required: bool = False,
) -> str:
    if value is None:
        if required:
            raise RuleError(f"{where}: '{field_name}' is required")
        return ANY
    if not isinstance(value, str):
        raise RuleError(f"{where}: '{field_name}' must be a string, got {value!r}")
    normalised = value.strip().upper()
    if normalised not in allowed:
        raise RuleError(
            f"{where}: '{field_name}' is {value!r}, expected one of {', '.join(allowed)}"
        )
    return normalised


def _to_int(text: str, field_name: str) -> int:
    try:
        return int(text.strip())
    except ValueError as exc:
        raise RuleError(f"{field_name}: {text.strip()!r} is not a number") from exc


def _check_port(port: int, field_name: str) -> int:
    if not MIN_PORT <= port <= MAX_PORT:
        raise RuleError(f"{field_name}: port {port} is outside {MIN_PORT}-{MAX_PORT}")
    return port

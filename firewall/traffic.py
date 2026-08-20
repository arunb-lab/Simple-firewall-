"""Sources of packets for the engine to judge.

Two are provided: a deterministic generator of plausible traffic for demos and
teaching, and a reader for JSON Lines files so that captured or hand-written
traffic can be replayed.
"""

from __future__ import annotations

import json
import random
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import IO

from firewall.errors import PacketError
from firewall.packets import Packet

#: Services a simulated host might reach for, as (protocol, port, weight).
#: Protocol and port are chosen together so the traffic stays plausible --
#: there is no such thing as UDP port 443 in this model.
_SERVICES = (
    ("TCP", 443, 8),  # HTTPS
    ("TCP", 80, 5),  # HTTP
    ("UDP", 53, 5),  # DNS
    ("UDP", 123, 2),  # NTP
    ("ICMP", None, 2),  # ping
    ("TCP", 22, 3),  # SSH
    ("TCP", 3389, 2),  # RDP
    ("TCP", 3306, 1),  # MySQL
    ("TCP", 8080, 1),  # dev HTTP
)

_LOCAL_HOSTS = ("192.168.1.10", "192.168.1.11", "192.168.1.15", "192.168.1.20")
_REMOTE_HOSTS = ("8.8.8.8", "1.1.1.1", "10.0.0.5", "203.0.113.10", "198.51.100.7")

#: Ports the operating system hands out to clients (IANA dynamic range).
_EPHEMERAL_RANGE = (49152, 65535)


def simulated_traffic(count: int, seed: int | None = None) -> Iterator[Packet]:
    """Yield ``count`` synthetic packets.

    Each packet is a client on one side reaching a well-known service on the
    other, so the stream resembles what a real filter would see. Passing a
    ``seed`` makes the sequence reproducible, which matters for demos and
    tests; without one the stream differs on every run.
    """
    if count < 0:
        raise ValueError(f"count must not be negative, got {count}")

    rng = random.Random(seed)
    services = [(protocol, port) for protocol, port, _ in _SERVICES]
    weights = [weight for _, _, weight in _SERVICES]

    for _ in range(count):
        direction = rng.choice(("IN", "OUT"))
        protocol, dst_port = rng.choices(services, weights=weights)[0]

        if direction == "IN":
            src, dst = rng.choice(_REMOTE_HOSTS), rng.choice(_LOCAL_HOSTS)
        else:
            src, dst = rng.choice(_LOCAL_HOSTS), rng.choice(_REMOTE_HOSTS)

        src_port = None if protocol == "ICMP" else rng.randint(*_EPHEMERAL_RANGE)

        yield Packet(
            src_ip=src,
            dst_ip=dst,
            protocol=protocol,
            direction=direction,
            src_port=src_port,
            dst_port=dst_port,
        )


def packets_from_jsonl(source: str | Path | IO[str]) -> Iterator[Packet]:
    """Read packets from a JSON Lines file, one JSON object per line.

    ``source`` may be a path, an open text stream, or ``"-"`` for stdin. Blank
    lines and ``#`` comments are skipped; a bad line reports its line number.
    """
    if isinstance(source, (str, Path)) and str(source) != "-":
        with Path(source).open("r", encoding="utf-8") as handle:
            yield from _read_lines(handle, str(source))
    elif isinstance(source, (str, Path)):
        yield from _read_lines(sys.stdin, "<stdin>")
    else:
        yield from _read_lines(source, getattr(source, "name", "<stream>"))


def _read_lines(handle: IO[str], origin: str) -> Iterator[Packet]:
    for line_number, raw in enumerate(handle, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            raise PacketError(f"{origin}:{line_number}: not valid JSON: {exc}") from exc
        try:
            yield Packet.from_dict(data)
        except PacketError as exc:
            raise PacketError(f"{origin}:{line_number}: {exc}") from exc

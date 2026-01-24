from dataclasses import dataclass
from ipaddress import ip_network, ip_address
from typing import Optional, Literal

Action = Literal["ALLOW", "DENY"]
Protocol = Literal["TCP", "UDP", "ANY"]
Direction = Literal["IN", "OUT", "ANY"]

@dataclass(frozen=True)
class Rule:
    name: str
    action: Action
    src_cidr: str = "0.0.0.0/0"
    dst_cidr: str = "0.0.0.0/0"
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Protocol = "ANY"
    direction: Direction = "ANY"

    def matches(self, packet: dict) -> bool:
        # packet keys: src_ip, dst_ip, src_port, dst_port, protocol, direction
        src_ok = ip_address(packet["src_ip"]) in ip_network(self.src_cidr, strict=False)
        dst_ok = ip_address(packet["dst_ip"]) in ip_network(self.dst_cidr, strict=False)

        if not (src_ok and dst_ok):
            return False

        if self.protocol != "ANY" and packet["protocol"] != self.protocol:
            return False

        if self.direction != "ANY" and packet["direction"] != self.direction:
            return False

        if self.src_port is not None and packet["src_port"] != self.src_port:
            return False

        if self.dst_port is not None and packet["dst_port"] != self.dst_port:
            return False

        return True

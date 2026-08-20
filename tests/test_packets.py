"""Tests for packet parsing and validation."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from ipaddress import IPv4Address, IPv6Address

import pytest

from firewall.errors import PacketError
from firewall.packets import Packet


class TestConstruction:
    def test_string_addresses_are_parsed(self):
        packet = Packet("10.0.0.1", "10.0.0.2", "TCP", "IN")
        assert isinstance(packet.src_ip, IPv4Address)
        assert isinstance(packet.dst_ip, IPv4Address)

    def test_ipv6_is_supported(self):
        packet = Packet("2001:db8::1", "2001:db8::2", "TCP", "OUT", dst_port=443)
        assert isinstance(packet.src_ip, IPv6Address)

    def test_protocol_and_direction_are_normalised(self):
        packet = Packet("10.0.0.1", "10.0.0.2", " tcp ", "in")
        assert packet.protocol == "TCP"
        assert packet.direction == "IN"

    def test_ports_default_to_none(self):
        packet = Packet("10.0.0.1", "10.0.0.2", "ICMP", "OUT")
        assert packet.src_port is None
        assert packet.dst_port is None

    def test_packets_are_immutable(self):
        packet = Packet("10.0.0.1", "10.0.0.2", "TCP", "IN")
        with pytest.raises(FrozenInstanceError):
            packet.protocol = "UDP"


class TestValidation:
    @pytest.mark.parametrize("bad_ip", ["not-an-ip", "999.1.1.1", "", None, 42])
    def test_invalid_address_is_rejected(self, bad_ip):
        with pytest.raises(PacketError, match="src_ip"):
            Packet(bad_ip, "10.0.0.2", "TCP", "IN")

    def test_unknown_protocol_is_rejected(self):
        with pytest.raises(PacketError, match="protocol"):
            Packet("10.0.0.1", "10.0.0.2", "SCTP", "IN")

    def test_unknown_direction_is_rejected(self):
        with pytest.raises(PacketError, match="direction"):
            Packet("10.0.0.1", "10.0.0.2", "TCP", "SIDEWAYS")

    @pytest.mark.parametrize("bad_port", [-1, 65536, 70000])
    def test_out_of_range_port_is_rejected(self, bad_port):
        with pytest.raises(PacketError, match="outside"):
            Packet("10.0.0.1", "10.0.0.2", "TCP", "IN", dst_port=bad_port)

    @pytest.mark.parametrize("bad_port", ["22", 22.0, True])
    def test_non_integer_port_is_rejected(self, bad_port):
        with pytest.raises(PacketError, match="integer port"):
            Packet("10.0.0.1", "10.0.0.2", "TCP", "IN", dst_port=bad_port)

    def test_boundary_ports_are_accepted(self):
        packet = Packet("10.0.0.1", "10.0.0.2", "TCP", "IN", src_port=0, dst_port=65535)
        assert (packet.src_port, packet.dst_port) == (0, 65535)


class TestSerialisation:
    def test_round_trips_through_a_dict(self, ssh_packet):
        assert Packet.from_dict(ssh_packet.to_dict()) == ssh_packet

    def test_missing_required_field_names_the_field(self):
        with pytest.raises(PacketError, match="dst_ip"):
            Packet.from_dict({"src_ip": "10.0.0.1", "protocol": "TCP", "direction": "IN"})

    def test_unknown_field_is_reported(self):
        data = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "direction": "IN",
            "dest_port": 22,  # typo for dst_port
        }
        with pytest.raises(PacketError, match="dest_port"):
            Packet.from_dict(data)

    def test_non_object_is_rejected(self):
        with pytest.raises(PacketError, match="must be an object"):
            Packet.from_dict(["10.0.0.1"])


class TestFormatting:
    def test_ipv4_endpoints_read_as_host_colon_port(self, ssh_packet):
        assert str(ssh_packet) == "IN TCP 203.0.113.10:51515 -> 192.168.1.10:22"

    def test_ipv6_endpoints_are_bracketed(self):
        packet = Packet("2001:db8::1", "2001:db8::2", "TCP", "OUT", 1234, 443)
        assert str(packet) == "OUT TCP [2001:db8::1]:1234 -> [2001:db8::2]:443"

    def test_portless_packet_omits_the_port(self):
        assert str(Packet("10.0.0.1", "10.0.0.2", "ICMP", "OUT")) == "OUT ICMP 10.0.0.1 -> 10.0.0.2"

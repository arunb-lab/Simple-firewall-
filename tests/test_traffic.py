"""Tests for the traffic sources."""

from __future__ import annotations

import io
import json

import pytest

from firewall.errors import PacketError
from firewall.packets import Packet
from firewall.traffic import packets_from_jsonl, simulated_traffic


class TestSimulatedTraffic:
    def test_it_yields_the_requested_number(self):
        assert len(list(simulated_traffic(25, seed=1))) == 25

    def test_zero_packets_is_allowed(self):
        assert list(simulated_traffic(0)) == []

    def test_a_negative_count_is_rejected(self):
        with pytest.raises(ValueError, match="negative"):
            list(simulated_traffic(-1))

    def test_the_same_seed_reproduces_the_same_stream(self):
        first = list(simulated_traffic(20, seed=42))
        second = list(simulated_traffic(20, seed=42))
        assert first == second

    def test_different_seeds_diverge(self):
        assert list(simulated_traffic(20, seed=1)) != list(simulated_traffic(20, seed=2))

    def test_every_packet_is_valid(self):
        for packet in simulated_traffic(200, seed=7):
            assert isinstance(packet, Packet)
            assert packet.direction in ("IN", "OUT")
            assert packet.protocol in ("TCP", "UDP", "ICMP")

    def test_icmp_packets_carry_no_ports(self):
        icmp = [p for p in simulated_traffic(300, seed=3) if p.protocol == "ICMP"]
        assert icmp, "the generator should produce some ICMP traffic"
        assert all(p.src_port is None and p.dst_port is None for p in icmp)

    def test_ports_are_paired_with_a_plausible_protocol(self):
        # Port 443 is TCP; the generator must not invent UDP/443.
        for packet in simulated_traffic(300, seed=5):
            if packet.dst_port in (22, 80, 443, 3306, 3389, 8080):
                assert packet.protocol == "TCP"
            if packet.dst_port in (53, 123):
                assert packet.protocol == "UDP"

    def test_clients_use_ephemeral_source_ports(self):
        for packet in simulated_traffic(100, seed=9):
            if packet.src_port is not None:
                assert 49152 <= packet.src_port <= 65535

    def test_inbound_traffic_arrives_from_outside_the_lan(self):
        for packet in simulated_traffic(100, seed=11):
            if packet.direction == "IN":
                assert not str(packet.src_ip).startswith("192.168.1.")


class TestJsonLines:
    def test_it_reads_one_packet_per_line(self, tmp_path):
        path = tmp_path / "traffic.jsonl"
        path.write_text(
            "\n".join(
                json.dumps(
                    {
                        "src_ip": "10.0.0.1",
                        "dst_ip": "10.0.0.2",
                        "protocol": "TCP",
                        "direction": "IN",
                        "dst_port": port,
                    }
                )
                for port in (22, 80)
            ),
            encoding="utf-8",
        )
        assert [p.dst_port for p in packets_from_jsonl(path)] == [22, 80]

    def test_blank_lines_and_comments_are_skipped(self, tmp_path):
        path = tmp_path / "traffic.jsonl"
        path.write_text(
            '# a comment\n\n{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2",'
            '"protocol":"ICMP","direction":"OUT"}\n\n',
            encoding="utf-8",
        )
        assert len(list(packets_from_jsonl(path))) == 1

    def test_it_reads_an_open_stream(self):
        stream = io.StringIO(
            '{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","protocol":"TCP","direction":"IN"}\n'
        )
        assert len(list(packets_from_jsonl(stream))) == 1

    def test_a_malformed_line_reports_its_line_number(self, tmp_path):
        path = tmp_path / "traffic.jsonl"
        path.write_text(
            '{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","protocol":"TCP","direction":"IN"}\n{oops\n',
            encoding="utf-8",
        )
        with pytest.raises(PacketError, match=r":2: not valid JSON"):
            list(packets_from_jsonl(path))

    def test_an_invalid_packet_reports_its_line_number(self, tmp_path):
        path = tmp_path / "traffic.jsonl"
        path.write_text(
            '{"src_ip":"nope","dst_ip":"10.0.0.2","protocol":"TCP","direction":"IN"}\n',
            encoding="utf-8",
        )
        with pytest.raises(PacketError, match=r":1: src_ip"):
            list(packets_from_jsonl(path))

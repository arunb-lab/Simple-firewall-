"""Shared fixtures for the test suite."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from firewall.packets import Packet

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def sample_rules_path() -> Path:
    """The ruleset shipped with the project."""
    return REPO_ROOT / "rules.json"


@pytest.fixture
def write_rules(tmp_path):
    """Return a helper that writes a rule document and gives back its path."""

    def _write(document, name: str = "rules.json") -> Path:
        path = tmp_path / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    return _write


@pytest.fixture
def ssh_packet() -> Packet:
    """An inbound SSH connection attempt from the internet."""
    return Packet("203.0.113.10", "192.168.1.10", "TCP", "IN", 51515, 22)

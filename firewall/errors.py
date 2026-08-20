"""Exception types raised by the firewall package.

Every error the package raises derives from :class:`FirewallError`, so callers
can catch that one type when they do not care which layer failed.
"""

from __future__ import annotations


class FirewallError(Exception):
    """Base class for every error raised by this package."""


class RuleError(FirewallError):
    """A rule definition is missing, malformed, or contradictory."""


class PacketError(FirewallError):
    """A packet description is missing a field or holds an invalid value."""

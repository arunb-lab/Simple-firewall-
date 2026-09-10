"""Audit logging of firewall decisions as JSON Lines.

Each decision is written as one self-contained JSON object per line, which is
the format log shippers and ``jq`` expect and which survives a crash mid-run
without corrupting earlier entries.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - import cycle only matters to type checkers
    from firewall.engine import Decision


class DecisionLogger:
    """Append decisions to a JSON Lines file.

    The file is opened once and held open, so a long run does not pay for a
    reopen per packet. Use it as a context manager, or call :meth:`close`.
    """

    def __init__(self, logfile: str | Path = "firewall.log") -> None:
        self.path = Path(logfile)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open("a", encoding="utf-8")

    def log(self, decision: Decision) -> dict[str, Any]:
        """Write one decision and return the record as it was serialised."""
        record = decision.to_dict()
        record["timestamp"] = datetime.now(timezone.utc).isoformat()
        self._handle.write(json.dumps(record) + "\n")
        self._handle.flush()
        return record

    def close(self) -> None:
        """Close the underlying file. Safe to call more than once."""
        if not self._handle.closed:
            self._handle.close()

    def __enter__(self) -> DecisionLogger:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


class NullLogger:
    """A logger that discards everything, for tests and ``--no-log`` runs."""

    def log(self, decision: Decision) -> dict[str, Any]:
        return decision.to_dict()

    def close(self) -> None:
        pass

    def __enter__(self) -> NullLogger:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        pass

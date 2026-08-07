"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from datetime import datetime, timezone


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline).

    MONITORING & INCIDENT RESPONSE: every request carries a correlation
    ``request_id`` that ties an input to its output decision, so an incident
    can be reconstructed end-to-end (source → model → sink). This layer never
    blocks — it makes the other layers reviewable.
    """

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store the input and start time keyed by a correlation id.

        Returns the request_id so the caller can pass the same id to
        ``record_output`` and keep the trace correlated.
        """
        rid = request_id or f"{user_id}-{len(self.logs) + len(self._open) + 1}"
        self._open[rid] = {
            "user_id": user_id,
            "input": text,
            "start": time.time(),
            "ts_input": utc_now_iso(),
        }
        return rid

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Close the trace: record output, which layer decided, and latency."""
        meta = self._open.pop(request_id, None) if request_id else None
        start = meta["start"] if meta else time.time()
        entry = {
            "request_id": request_id or f"{user_id}-{len(self.logs) + 1}",
            "user_id": user_id,
            "input": meta["input"] if meta else None,
            "output": text,
            "blocked": blocked,
            "layer": layer,
            "latency_ms": round((time.time() - start) * 1000, 2),
            "ts_input": meta["ts_input"] if meta else None,
            "ts_output": utc_now_iso(),
        }
        self.logs.append(entry)
        return entry

    def export_json(self, filepath: str = "outputs/audit_log.json"):
        """Write logs to disk (JSON array)."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

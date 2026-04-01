"""
event_emitter.py
================
Privacy-first telemetry pipeline to the Control Plane.
Queues MetadataEvents locally in SQLite, flushes in batches.

Invariants:
  - No raw prompts ever leave the device
  - No PII values ever leave the device
  - No response text ever leaves the device
  - Only anonymized metadata (pii types, scores, latency) is sent

Flush behavior:
  - Normal: every 10 seconds
  - On GUARD_BLOCKED: immediate flush for real-time alerting
"""

import asyncio
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

import httpx
import structlog

from app.config import Settings
from app.contracts.enums import EventType
from app.contracts.events import (
    MetadataEvent, GuardMeta, RequestMeta, DeviceInfo,
)
from app.contracts.guard import GuardResult

logger = structlog.get_logger(__name__)

DB_PATH = Path("foretyx_events.db")


class EventEmitter:
    """
    Privacy-preserving event telemetry with local SQLite queue.
    Events are batched and flushed to the Control Plane on a timer.
    """

    def __init__(self, settings: Settings):
        self._control_plane_url = settings.control_plane_url
        self._bridge_token = settings.bridge_token.get_secret_value()
        self._flush_task: Optional[asyncio.Task] = None
        self._device_info = DeviceInfo()
        self._init_db()

    def _init_db(self):
        """Create the local event queue table."""
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS outbound_events (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                event_json TEXT    NOT NULL,
                created_at TEXT    NOT NULL,
                sent       INTEGER DEFAULT 0
            )
        """)
        conn.commit()
        conn.close()
        logger.debug("event_emitter_db_initialized", path=str(DB_PATH))

    def queue_event(
        self,
        guard_result: GuardResult,
        model_requested: str,
        model_allowed: bool,
        org_id: str,
        user_id: str,
        event_type: EventType,
    ):
        """
        Build a MetadataEvent from GuardResult and queue it locally.
        NEVER includes raw prompt, clean_text, PII values, or response text.
        """
        event = MetadataEvent(
            org_id=org_id,
            user_id=user_id,
            event_type=event_type,
            device=self._device_info,
            guard=GuardMeta.from_guard_result(guard_result),
            request=RequestMeta(
                model_requested=model_requested,
                model_allowed=model_allowed,
                prompt_token_estimate=int(
                    len(guard_result.clean_text.split()) * 1.3
                ),
                blocked=guard_result.blocked,
                block_reason=guard_result.block_reason,
            ),
        )

        conn = sqlite3.connect(str(DB_PATH))
        conn.execute(
            "INSERT INTO outbound_events (event_json, created_at) VALUES (?, ?)",
            (event.model_dump_json(), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        conn.close()

        logger.debug("event_queued", event_type=event_type.value, org_id=org_id)

        # Immediate flush on GUARD_BLOCKED for real-time alerting
        if event_type == EventType.GUARD_BLOCKED and self._bridge_token:
            asyncio.create_task(self.flush())

    async def flush(self):
        """Flush queued events to the Control Plane. Retries on next cycle if failed."""
        if not self._bridge_token:
            return

        conn = sqlite3.connect(str(DB_PATH))
        rows = conn.execute(
            "SELECT id, event_json FROM outbound_events WHERE sent=0 LIMIT 50"
        ).fetchall()
        conn.close()

        if not rows:
            return

        ids = [r[0] for r in rows]
        events = [json.loads(r[1]) for r in rows]

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(
                    f"{self._control_plane_url}/events",
                    json={"events": events},
                    headers={"Authorization": f"Bearer {self._bridge_token}"},
                )

            if resp.status_code == 200:
                conn = sqlite3.connect(str(DB_PATH))
                placeholders = ",".join("?" * len(ids))
                conn.execute(
                    f"UPDATE outbound_events SET sent=1 WHERE id IN ({placeholders})",
                    ids,
                )
                conn.commit()
                conn.close()
                logger.info("events_flushed", count=len(ids))
            else:
                logger.warning(
                    "event_flush_failed",
                    status_code=resp.status_code,
                    count=len(ids),
                )

        except Exception as e:
            logger.warning("event_flush_error", error=str(e), count=len(ids))

    async def start_flush_loop(self):
        """Background task: flush events every 10 seconds."""
        while True:
            await asyncio.sleep(10)
            try:
                await self.flush()
            except Exception as e:
                logger.error("flush_loop_error", error=str(e))

    async def shutdown(self):
        """Final flush on shutdown."""
        logger.info("event_emitter_shutdown_flush")
        await self.flush()

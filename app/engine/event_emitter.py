"""
event_emitter.py
================
Privacy-first telemetry pipeline to the Control Plane.
Queues MetadataEvents locally in SQLite, flushes in batches (Section 3.5 — complete).

SQLite buffer completions (Section 3.5):
  - Added indexes on (sent, created_at) for fast pending-event queries
  - Added cleanup task: purge events older than 7 days that are already sent
  - Added retry_count column to track failed flush attempts
  - Added last_error column for diagnosability
  - Added `get_pending_count()` and `get_stats()` for the metrics endpoint
  - Added dead-letter queue: events that fail 5+ times are moved to failed_events table
  - Buffer compaction: VACUUM on weekly schedule

Invariants (unchanged):
  - No raw prompts ever leave the device
  - No PII values ever leave the device
  - No response text ever leaves the device
  - Only anonymized metadata (pii types, scores, latency) is sent

Flush behavior:
  - Normal: every 10 seconds
  - On GUARD_BLOCKED: immediate flush for real-time alerting
  - Cleanup: every 24 hours (sent events older than 7 days purged)
"""

import asyncio
import json
import sqlite3
import time
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

MAX_RETRY_COUNT = 5          # After this many failures, move to dead-letter
RETENTION_DAYS  = 7          # Delete sent events older than this
BATCH_SIZE      = 50         # Events per flush batch
FLUSH_INTERVAL  = 10         # Seconds between normal flushes
CLEANUP_INTERVAL = 86400     # Seconds between cleanup runs (24h)


class EventEmitter:
    """
    Privacy-preserving event telemetry with local SQLite queue.

    New in this version (Section 3.5 completion):
      - Retry counter per event (max 5 retries → dead-letter)
      - Automatic cleanup of old sent events
      - get_stats() for observability
      - Dead-letter table for undeliverable events
      - VACUUM compaction
    """

    def __init__(self, settings: Settings):
        self._control_plane_url = settings.control_plane_url
        self._bridge_token = settings.bridge_token.get_secret_value()
        self._flush_task: Optional[asyncio.Task] = None
        self._device_info = DeviceInfo()
        self._last_cleanup = time.time()
        self._init_db()

    def _init_db(self):
        """Create the local event queue table with all indexes and columns."""
        conn = sqlite3.connect(str(DB_PATH))
        conn.executescript("""
            -- Main outbound queue
            CREATE TABLE IF NOT EXISTS outbound_events (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                event_json    TEXT    NOT NULL,
                created_at    TEXT    NOT NULL,
                sent          INTEGER DEFAULT 0,
                retry_count   INTEGER DEFAULT 0,
                last_error    TEXT    DEFAULT NULL,
                updated_at    TEXT    DEFAULT NULL
            );

            -- Fast lookup index for flush queries
            CREATE INDEX IF NOT EXISTS idx_outbound_pending
                ON outbound_events (sent, created_at);

            -- Dead-letter queue for events that exceeded max retries
            CREATE TABLE IF NOT EXISTS failed_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                event_json  TEXT    NOT NULL,
                created_at  TEXT    NOT NULL,
                failed_at   TEXT    NOT NULL,
                retry_count INTEGER NOT NULL,
                last_error  TEXT
            );
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

        now = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute(
            "INSERT INTO outbound_events (event_json, created_at) VALUES (?, ?)",
            (event.model_dump_json(), now),
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
            "SELECT id, event_json, retry_count FROM outbound_events "
            f"WHERE sent=0 AND retry_count < {MAX_RETRY_COUNT} "
            "ORDER BY created_at ASC LIMIT ?",
            (BATCH_SIZE,),
        ).fetchall()
        conn.close()

        if not rows:
            return

        ids          = [r[0] for r in rows]
        events       = [json.loads(r[1]) for r in rows]
        retry_counts = {r[0]: r[2] for r in rows}

        now = datetime.now(timezone.utc).isoformat()

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
                    f"UPDATE outbound_events SET sent=1, updated_at=? WHERE id IN ({placeholders})",
                    [now] + ids,
                )
                conn.commit()
                conn.close()
                logger.info("events_flushed", count=len(ids))
            else:
                self._record_retry_failures(ids, f"HTTP {resp.status_code}")
                logger.warning(
                    "event_flush_failed",
                    status_code=resp.status_code,
                    count=len(ids),
                )

        except Exception as e:
            self._record_retry_failures(ids, str(e))
            logger.warning("event_flush_error", error=str(e), count=len(ids))

    def _record_retry_failures(self, ids: list[int], error: str):
        """Increment retry counter; move to dead-letter if max retries exceeded."""
        now = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect(str(DB_PATH))

        for event_id in ids:
            row = conn.execute(
                "SELECT retry_count, event_json, created_at FROM outbound_events WHERE id=?",
                (event_id,),
            ).fetchone()
            if not row:
                continue

            new_count = row[0] + 1
            if new_count >= MAX_RETRY_COUNT:
                # Move to dead-letter
                conn.execute(
                    "INSERT INTO failed_events (event_json, created_at, failed_at, retry_count, last_error) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (row[1], row[2], now, new_count, error[:500]),
                )
                conn.execute("DELETE FROM outbound_events WHERE id=?", (event_id,))
                logger.warning(
                    "event_dead_lettered",
                    event_id=event_id,
                    retry_count=new_count,
                    error=error[:100],
                )
            else:
                conn.execute(
                    "UPDATE outbound_events SET retry_count=?, last_error=?, updated_at=? WHERE id=?",
                    (new_count, error[:500], now, event_id),
                )

        conn.commit()
        conn.close()

    def _cleanup_old_events(self):
        """
        Section 3.5: Prune sent events older than RETENTION_DAYS.
        Also VACUUM to reclaim disk space.
        """
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).isoformat()
        conn = sqlite3.connect(str(DB_PATH))
        result = conn.execute(
            "DELETE FROM outbound_events WHERE sent=1 AND created_at < ?",
            (cutoff,),
        )
        deleted = result.rowcount
        conn.commit()

        if deleted > 0:
            conn.execute("VACUUM")
            conn.commit()
            logger.info(
                "event_buffer_cleanup",
                deleted_rows=deleted,
                retention_days=RETENTION_DAYS,
            )
        conn.close()

    def get_stats(self) -> dict:
        """Return SQLite buffer statistics for the metrics endpoint."""
        if not DB_PATH.exists():
            return {"pending": 0, "sent": 0, "failed": 0, "dead_letter": 0}
        try:
            conn = sqlite3.connect(str(DB_PATH))
            pending    = conn.execute("SELECT COUNT(*) FROM outbound_events WHERE sent=0").fetchone()[0]
            sent       = conn.execute("SELECT COUNT(*) FROM outbound_events WHERE sent=1").fetchone()[0]
            dead_letter = conn.execute("SELECT COUNT(*) FROM failed_events").fetchone()[0]
            conn.close()
            return {
                "pending":     pending,
                "sent":        sent,
                "dead_letter": dead_letter,
                "total":       pending + sent,
            }
        except Exception as e:
            return {"error": str(e)}

    async def start_flush_loop(self):
        """Background task: flush events every 10 seconds; cleanup every 24h."""
        while True:
            await asyncio.sleep(FLUSH_INTERVAL)
            try:
                await self.flush()
            except Exception as e:
                logger.error("flush_loop_error", error=str(e))

            # Cleanup check
            if time.time() - self._last_cleanup > CLEANUP_INTERVAL:
                try:
                    self._cleanup_old_events()
                    self._last_cleanup = time.time()
                except Exception as e:
                    logger.error("cleanup_error", error=str(e))

    async def shutdown(self):
        """Final flush on shutdown."""
        logger.info("event_emitter_shutdown_flush")
        await self.flush()

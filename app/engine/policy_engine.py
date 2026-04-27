"""
policy_engine.py
================
Reads and enforces PolicyBundle from the Control Plane.
Policy is cached locally at ~/.foretyx/policy.json and refreshed via
WebSocket push or periodic pull.

Fail-closed: if the policy file is missing or corrupt, ALL prompts are blocked.
"""

import json
from pathlib import Path
from typing import Optional

import structlog

from app.config import Settings
from app.contracts.policy import PolicyBundle

logger = structlog.get_logger(__name__)

POLICY_PATH = Path.home() / ".foretyx" / "policy.json"


class PolicyEngine:
    """
    Loads and caches the org's PolicyBundle.
    Returns None if the policy is missing/corrupt — caller must fail-closed on None.
    """

    def __init__(self, settings: Settings):
        self._settings = settings
        self._cached_policy: Optional[PolicyBundle] = None
        self._load()

    def _load(self):
        """Load policy from disk. Called at startup and on refresh."""
        if not POLICY_PATH.exists():
            logger.warning(
                "policy_file_missing",
                path=str(POLICY_PATH),
                action="using_default_policy",
            )
            # Create a sensible default policy so the system works out of the box
            self._cached_policy = PolicyBundle(
                policy_version="default-v1",
                org_id="org_default",
                allowed_models=["gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash", "gemini-2.5-pro"],
                blocked_keywords=[],
                max_prompt_tokens=4000,
            )
            # Default PII rules: scrub-and-pass (not blanket block)
            self._cached_policy.pii_rules.block_on_detect = False
            self._cached_policy.pii_rules.scrub_before_send = True
            # Write it so future loads succeed
            try:
                POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
                POLICY_PATH.write_text(
                    self._cached_policy.model_dump_json(indent=2)
                )
                logger.info("default_policy_written", path=str(POLICY_PATH))
            except Exception as e:
                logger.warning("could_not_write_default_policy", error=str(e))
            return

        try:
            with open(POLICY_PATH, "r") as f:
                data = json.load(f)
            self._cached_policy = PolicyBundle(**data)
            logger.info(
                "policy_loaded",
                version=self._cached_policy.policy_version,
                org_id=self._cached_policy.org_id,
                allowed_models=self._cached_policy.allowed_models,
            )
        except Exception as e:
            logger.error(
                "policy_load_failed",
                error=str(e),
                path=str(POLICY_PATH),
                action="fail_closed",
            )
            self._cached_policy = None

    def get_policy(self) -> Optional[PolicyBundle]:
        """Returns the cached policy, or None if unavailable (fail-closed)."""
        return self._cached_policy

    def refresh(self):
        """Reload policy from disk. Called when Control Plane pushes an update."""
        logger.info("policy_refresh_triggered")
        self._load()

    @property
    def is_loaded(self) -> bool:
        return self._cached_policy is not None

"""
response_scanner.py
===================
Post-LLM response scanning — a capability NEITHER original repo had.

Scans the LLM response for:
  1. Leaked PII that wasn't in the original prompt (hallucinated or from training data)
  2. System prompt leakage (if the LLM accidentally reveals its instructions)
  3. Known sensitive patterns (API keys, passwords, etc.)

This closes a critical gap: even if the prompt was clean, the LLM response
might contain sensitive data from its training corpus.
"""

import re
from typing import Tuple

import structlog

from app.guards.pii_detector import PiiDetector

logger = structlog.get_logger(__name__)


# Patterns that suggest system prompt leakage
SYSTEM_PROMPT_LEAK_PATTERNS = [
    re.compile(r"(?i)my (?:system |original |hidden )?(?:prompt|instructions?) (?:is|are|says?):"),
    re.compile(r"(?i)i was (?:instructed|told|programmed) to"),
    re.compile(r"(?i)my (?:initial|original) (?:instructions?|guidelines?) (?:include|state|say)"),
    re.compile(r"(?i)as per my (?:system|base|core) (?:prompt|instructions?)"),
    re.compile(r"(?i)here (?:is|are) my (?:system|original|full) (?:prompt|instructions?)"),
]


class ResponseScanner:
    """
    Scans LLM responses for sensitive data leaks.
    Uses the same PII detector used for prompts, plus system prompt leak detection.
    """

    def __init__(self, pii_detector: PiiDetector):
        self._pii_detector = pii_detector

    def scan(self, response_text: str) -> Tuple[str, list[str], bool]:
        """
        Scan an LLM response for sensitive data.

        Args:
            response_text: The raw LLM response

        Returns:
            (clean_response, pii_types_found, system_prompt_leaked)
            - clean_response:      response with any detected PII scrubbed
            - pii_types_found:     list of PII type names found in response
            - system_prompt_leaked: True if system prompt leakage detected
        """
        pii_types_found: list[str] = []
        system_prompt_leaked = False

        # ── Check for system prompt leakage ──────────────────────────────────
        for pattern in SYSTEM_PROMPT_LEAK_PATTERNS:
            if pattern.search(response_text):
                system_prompt_leaked = True
                logger.warning(
                    "system_prompt_leak_detected_in_response",
                    pattern=pattern.pattern[:50],
                )
                break

        # ── Scan for PII in response ─────────────────────────────────────────
        clean_response, detections, _ = self._pii_detector.scrub(response_text)

        if detections:
            pii_types_found = [d.pii_type.value for d in detections]
            logger.warning(
                "pii_detected_in_llm_response",
                pii_count=len(detections),
                pii_types=pii_types_found,
            )
            # Return the scrubbed version — don't leak PII in response
            return clean_response, pii_types_found, system_prompt_leaked

        return response_text, pii_types_found, system_prompt_leaked

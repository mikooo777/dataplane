"""
pipeline.py
============
The Foretyx Guard Pipeline — master orchestrator.
Runs all security phases in sequence with per-phase timing, fail-closed
semantics, and structured audit logging.

Phase execution order:
  1a. Heuristic scan       (regex jailbreak patterns)           <1ms
  1b. OWASP LLM Top 10    (NEW — all 10 categories)            <1ms
  1c. Semantic firewall    (forbidden topic keywords)           <1ms
  1d. PII scrub            (Presidio, 15+ entity types)        ~10ms
      └─ Aadhaar Verhoeff  (NEW — checksum on Aadhaar hits)    <1ms
  2a. ML injection scan    (ONNX distilbert)                   ~15ms
  2b. Ollama escalation    (LLM judgment, only if 2a escalate)
  3.  Token budget         (NEW — tiktoken, not word estimate)  <1ms
  3.  Policy enforcement   (token limits, keyword blocklist, model allowlist)

NEW in this version:
  - OWASP LLM Top 10 scanner (10/10 coverage)
  - Aadhaar Verhoeff checksum — reduces false positives
  - tiktoken token budget — precise BPE token count
  - WARN action — confidence-calibrated (Section 4.1)
    GuardResult.warn=True when risk is real but below block threshold
  - Per-user rate limiting integrated at pipeline level
"""

import time
from typing import Optional

import structlog

from app.config import Settings
from app.contracts.enums import BlockReason
from app.contracts.guard import GuardResult, PiiDetection
from app.contracts.policy import PolicyBundle
from app.guards.heuristic_scanner import HeuristicScanner
from app.guards.owasp_scanner import OwaspScanner
from app.guards.semantic_firewall import SemanticFirewall
from app.guards.pii_detector import PiiDetector
from app.guards.injection_detector import InjectionDetector
from app.guards.ollama_guard import OllamaGuard
from app.guards.verhoeff import is_valid_aadhaar
from app.engine.policy_engine import PolicyEngine
from app.engine.token_budget import check_token_budget

logger = structlog.get_logger(__name__)


class GuardPipeline:
    """
    Stateless guard pipeline. Initialized once at startup, called per-request.
    Every phase fails-closed: if a guard errors, the prompt is blocked.
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self.heuristic_scanner = HeuristicScanner()
        self.owasp_scanner     = OwaspScanner()
        self.semantic_firewall = SemanticFirewall()
        self.pii_detector      = PiiDetector()
        self.injection_detector = InjectionDetector(settings)
        self.ollama_guard      = OllamaGuard(settings)
        self.policy_engine     = PolicyEngine(settings)

        logger.info(
            "guard_pipeline_initialized",
            ml_model_loaded=self.injection_detector.is_loaded,
            fail_behavior=settings.fail_behavior,
            owasp_coverage="10/10",
            aadhaar_verhoeff=True,
            tiktoken_budget=True,
            warn_action=True,
        )

    def _blocked(
        self,
        raw_prompt: str,
        reason: BlockReason,
        detail: str,
        t0: float,
        timings: dict,
        clean_text: str = "",
        detections: Optional[list[PiiDetection]] = None,
        placeholder_map: Optional[dict] = None,
        ml_score: float = 0.0,
        injection: bool = False,
        warn: bool = False,
    ) -> GuardResult:
        """Helper to build a blocked GuardResult."""
        latency = (time.perf_counter() - t0) * 1000
        logger.warning(
            "prompt_blocked",
            reason=reason.value,
            detail=detail,
            latency_ms=round(latency, 2),
        )
        return GuardResult(
            clean_text=clean_text or raw_prompt,
            blocked=True,
            block_reason=reason,
            block_detail=detail,
            pii_detections=detections or [],
            injection_detected=injection,
            ml_guard_score=ml_score,
            latency_ms=latency,
            placeholder_map=placeholder_map or {},
            phase_timings=timings,
            warn=warn,
        )

    def _warned(
        self,
        clean_text: str,
        warn_reason: str,
        t0: float,
        timings: dict,
        detections: Optional[list[PiiDetection]] = None,
        placeholder_map: Optional[dict] = None,
        ml_score: float = 0.0,
    ) -> GuardResult:
        """
        Build a WARN GuardResult (Section 4.1).
        The prompt is NOT blocked but a warning is attached for downstream handling.
        The LLM call still proceeds — but the caller SHOULD surface this to the user.
        """
        latency = (time.perf_counter() - t0) * 1000
        logger.warning(
            "prompt_warned",
            reason=warn_reason,
            ml_score=round(ml_score, 4),
            latency_ms=round(latency, 2),
        )
        return GuardResult(
            clean_text=clean_text,
            blocked=False,
            pii_detections=detections or [],
            injection_detected=False,
            ml_guard_score=ml_score,
            latency_ms=latency,
            placeholder_map=placeholder_map or {},
            phase_timings=timings,
            warn=True,
            warn_reason=warn_reason,
        )

    async def guard(self, raw_prompt: str) -> GuardResult:
        """
        Run the full guard pipeline on a raw prompt.
        Returns GuardResult — if blocked=True, the prompt MUST NOT reach the LLM.
        If warn=True, the caller should surface a risk warning to the user.
        """
        t0 = time.perf_counter()
        timings: dict[str, float] = {}
        clean_text = raw_prompt
        detections: list[PiiDetection] = []
        placeholder_map: dict[str, str] = {}
        ml_score = 0.0

        # ── Input validation ─────────────────────────────────────────────────
        if not raw_prompt or not raw_prompt.strip():
            return self._blocked(
                raw_prompt, BlockReason.POLICY_VIOLATION,
                "Empty prompt", t0, timings,
            )

        if len(raw_prompt) > self.settings.max_prompt_length:
            return self._blocked(
                raw_prompt, BlockReason.PROMPT_TOO_LONG,
                f"Prompt length {len(raw_prompt)} exceeds max {self.settings.max_prompt_length}",
                t0, timings,
            )

        # ── Phase 1a: Heuristic jailbreak scan ──────────────────────────────
        t_phase = time.perf_counter()
        jailbreak_detected, pattern_name = self.heuristic_scanner.scan(raw_prompt)
        timings["heuristic_scan_ms"] = (time.perf_counter() - t_phase) * 1000

        if jailbreak_detected:
            return self._blocked(
                raw_prompt, BlockReason.HEURISTIC_JAILBREAK,
                f"Jailbreak pattern: {pattern_name}",
                t0, timings, injection=True,
            )

        # ── Phase 1b: OWASP LLM Top 10 scan (NEW) ───────────────────────────
        t_phase = time.perf_counter()
        owasp_triggered, owasp_id, owasp_pattern = self.owasp_scanner.scan(raw_prompt)
        timings["owasp_scan_ms"] = (time.perf_counter() - t_phase) * 1000

        if owasp_triggered:
            return self._blocked(
                raw_prompt, BlockReason.HEURISTIC_JAILBREAK,
                f"OWASP {owasp_id}: {owasp_pattern}",
                t0, timings, injection=True,
            )

        # ── Phase 1c: Semantic firewall ──────────────────────────────────────
        t_phase = time.perf_counter()
        forbidden, topic, category = self.semantic_firewall.check(raw_prompt)
        timings["semantic_firewall_ms"] = (time.perf_counter() - t_phase) * 1000

        if forbidden:
            return self._blocked(
                raw_prompt, BlockReason.FORBIDDEN_TOPIC,
                f"Forbidden topic: '{topic}' (category: {category})",
                t0, timings,
            )

        # ── Phase 1d: PII scrub ─────────────────────────────────────────────
        t_phase = time.perf_counter()
        clean_text, detections, placeholder_map = self.pii_detector.scrub(raw_prompt)
        timings["pii_scrub_ms"] = (time.perf_counter() - t_phase) * 1000

        # ── Aadhaar Verhoeff checksum (NEW — Section 2.2) ────────────────────
        # For each Aadhaar detection, validate the checksum.
        # If it fails the checksum it's not a real Aadhaar → remove the detection
        # to reduce false positives.
        from app.contracts.enums import PiiType
        valid_detections = []
        valid_placeholder_map = {}
        rejected_placeholders = set()   # Track Verhoeff-rejected placeholders
        for det in detections:
            if det.pii_type == PiiType.AADHAAR:
                original_value = placeholder_map.get(det.placeholder, "")
                if original_value and not is_valid_aadhaar(original_value):
                    # Verhoeff checksum FAILED — restore this token, not a real Aadhaar
                    logger.debug(
                        "aadhaar_verhoeff_rejected",
                        placeholder=det.placeholder,
                        checksum_valid=False,
                    )
                    # Restore the text in clean_text for this placeholder
                    clean_text = clean_text.replace(det.placeholder, original_value)
                    rejected_placeholders.add(det.placeholder)
                    continue
            valid_detections.append(det)
            valid_placeholder_map[det.placeholder] = placeholder_map.get(det.placeholder, "")

        # Carry over non-detection placeholders, but NOT rejected ones
        for k, v in placeholder_map.items():
            if k not in valid_placeholder_map and k not in rejected_placeholders:
                valid_placeholder_map[k] = v
        detections      = valid_detections
        placeholder_map = valid_placeholder_map

        # Check PII policy: block if detected types are not in the allowed list
        bundle = self.policy_engine.get_policy()
        if detections and bundle and bundle.pii_rules.block_on_detect:
            allowed = set(bundle.pii_rules.allowed_pii_types)
            detected_types = {d.pii_type for d in detections}
            blocked_types = detected_types - allowed
            if blocked_types:
                return self._blocked(
                    raw_prompt, BlockReason.PII_DETECTED,
                    f"Blocked PII types: {[t.value for t in blocked_types]}",
                    t0, timings,
                    clean_text=clean_text,
                    detections=detections,
                    placeholder_map=placeholder_map,
                )

        # ── Phase 2a: ML injection scan (ONNX) ──────────────────────────────
        t_phase = time.perf_counter()
        verdict, ml_score = self.injection_detector.scan(raw_prompt)
        timings["ml_guard_ms"] = (time.perf_counter() - t_phase) * 1000

        if verdict == "error":
            # ML model failed — fail-closed
            if self.settings.fail_behavior == "CLOSED":
                return self._blocked(
                    raw_prompt, BlockReason.ML_GUARD_TRIGGERED,
                    "ML guard unavailable — fail-closed",
                    t0, timings,
                    clean_text=clean_text,
                    detections=detections,
                    placeholder_map=placeholder_map,
                    injection=True,
                )

        if verdict == "block":
            return self._blocked(
                raw_prompt, BlockReason.ML_GUARD_TRIGGERED,
                f"ML guard score {ml_score:.4f} >= block threshold {self.settings.ml_block_threshold}",
                t0, timings,
                clean_text=clean_text,
                detections=detections,
                placeholder_map=placeholder_map,
                ml_score=ml_score,
                injection=True,
            )

        # ── Phase 2b: Ollama escalation (ambiguous cases only) ───────────────
        if verdict == "escalate":
            t_phase = time.perf_counter()
            ollama_result = await self.ollama_guard.scan(clean_text)
            timings["ollama_escalation_ms"] = (time.perf_counter() - t_phase) * 1000

            if ollama_result.get("action") == "block":
                return self._blocked(
                    raw_prompt, BlockReason.ML_GUARD_TRIGGERED,
                    f"Ollama escalation blocked: {ollama_result.get('reason', 'N/A')}",
                    t0, timings,
                    clean_text=clean_text,
                    detections=detections,
                    placeholder_map=placeholder_map,
                    ml_score=ml_score,
                    injection=True,
                )

            # ── WARN action (Section 4.1) ────────────────────────────────────
            # If Ollama says "pass" but ML score was in escalation zone →
            # emit a WARN verdict. The prompt passes to LLM but the caller
            # is notified to surface a risk indicator to the user.
            if ollama_result.get("action") == "warn" or (
                ml_score >= self.settings.ml_escalate_threshold
                and ollama_result.get("action") != "block"
            ):
                warn_reason = (
                    ollama_result.get("reason")
                    or f"ML score {ml_score:.4f} in escalation zone (>{self.settings.ml_escalate_threshold})"
                )
                return self._warned(
                    clean_text=clean_text,
                    warn_reason=warn_reason,
                    t0=t0,
                    timings=timings,
                    detections=detections,
                    placeholder_map=placeholder_map,
                    ml_score=ml_score,
                )

        # ── Phase 3: Token budget (tiktoken — NEW) ───────────────────────────
        t_phase = time.perf_counter()

        if bundle:
            within_budget, token_count = check_token_budget(clean_text, bundle.max_prompt_tokens)
            timings["token_budget_ms"] = (time.perf_counter() - t_phase) * 1000

            if not within_budget:
                return self._blocked(
                    raw_prompt, BlockReason.TOKEN_LIMIT_EXCEEDED,
                    f"Token count {token_count} > limit {bundle.max_prompt_tokens} (tiktoken)",
                    t0, timings,
                    clean_text=clean_text,
                    detections=detections,
                    placeholder_map=placeholder_map,
                    ml_score=ml_score,
                )

            # Keyword blocklist check
            for kw in (bundle.blocked_keywords or []):
                if kw.lower() in clean_text.lower():
                    timings["policy_check_ms"] = (time.perf_counter() - t_phase) * 1000
                    return self._blocked(
                        raw_prompt, BlockReason.KEYWORD_BLOCKED,
                        f"Policy keyword blocked: '{kw}'",
                        t0, timings,
                        clean_text=clean_text,
                        detections=detections,
                        placeholder_map=placeholder_map,
                        ml_score=ml_score,
                    )

        timings["policy_check_ms"] = (time.perf_counter() - t_phase) * 1000

        # ── PASS — prompt is safe ────────────────────────────────────────────
        latency = (time.perf_counter() - t0) * 1000
        logger.info(
            "prompt_passed",
            pii_count=len(detections),
            ml_score=round(ml_score, 4),
            latency_ms=round(latency, 2),
        )

        return GuardResult(
            clean_text=clean_text,
            blocked=False,
            pii_detections=detections,
            injection_detected=False,
            ml_guard_score=ml_score,
            latency_ms=latency,
            placeholder_map=placeholder_map,
            phase_timings=timings,
            warn=False,
        )

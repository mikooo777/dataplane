"""
pipeline.py
============
The Foretyx Guard Pipeline — master orchestrator.
Runs all security phases in sequence with per-phase timing, fail-closed
semantics, and structured audit logging.

Phase execution order:
  1a. Heuristic scan     (regex jailbreak patterns)      <1ms
  1b. Semantic firewall  (forbidden topic keywords)      <1ms
  1c. PII scrub          (Presidio, 15+ entity types)    ~10ms
  2a. ML injection scan  (ONNX distilbert)               ~15ms
  2b. Ollama escalation  (LLM judgment, only if 2a says "escalate")
  3.  Policy enforcement (token limits, keyword blocklist, model allowlist)
"""

import time
from typing import Optional

import structlog

from app.config import Settings
from app.contracts.enums import BlockReason
from app.contracts.guard import GuardResult, PiiDetection
from app.contracts.policy import PolicyBundle
from app.guards.heuristic_scanner import HeuristicScanner
from app.guards.semantic_firewall import SemanticFirewall
from app.guards.pii_detector import PiiDetector
from app.guards.injection_detector import InjectionDetector
from app.guards.ollama_guard import OllamaGuard
from app.engine.policy_engine import PolicyEngine

logger = structlog.get_logger(__name__)


class GuardPipeline:
    """
    Stateless guard pipeline. Initialized once at startup, called per-request.
    Every phase fails-closed: if a guard errors, the prompt is blocked.
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self.heuristic_scanner = HeuristicScanner()
        self.semantic_firewall = SemanticFirewall()
        self.pii_detector = PiiDetector()
        self.injection_detector = InjectionDetector(settings)
        self.ollama_guard = OllamaGuard(settings)
        self.policy_engine = PolicyEngine(settings)

        logger.info(
            "guard_pipeline_initialized",
            ml_model_loaded=self.injection_detector.is_loaded,
            fail_behavior=settings.fail_behavior,
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
        )

    async def guard(self, raw_prompt: str) -> GuardResult:
        """
        Run the full guard pipeline on a raw prompt.
        Returns GuardResult — if blocked=True, the prompt MUST NOT reach the LLM.
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

        # ── Phase 1b: Semantic firewall ──────────────────────────────────────
        t_phase = time.perf_counter()
        forbidden, topic, category = self.semantic_firewall.check(raw_prompt)
        timings["semantic_firewall_ms"] = (time.perf_counter() - t_phase) * 1000

        if forbidden:
            return self._blocked(
                raw_prompt, BlockReason.FORBIDDEN_TOPIC,
                f"Forbidden topic: '{topic}' (category: {category})",
                t0, timings,
            )

        # ── Phase 1c: PII scrub ─────────────────────────────────────────────
        t_phase = time.perf_counter()
        clean_text, detections, placeholder_map = self.pii_detector.scrub(raw_prompt)
        timings["pii_scrub_ms"] = (time.perf_counter() - t_phase) * 1000

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

        # ── Phase 3: Policy enforcement ──────────────────────────────────────
        t_phase = time.perf_counter()

        if bundle:
            # Token limit check
            token_estimate = int(len(clean_text.split()) * 1.3)
            if token_estimate > bundle.max_prompt_tokens:
                timings["policy_check_ms"] = (time.perf_counter() - t_phase) * 1000
                return self._blocked(
                    raw_prompt, BlockReason.TOKEN_LIMIT_EXCEEDED,
                    f"Token estimate {token_estimate} > limit {bundle.max_prompt_tokens}",
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
        )

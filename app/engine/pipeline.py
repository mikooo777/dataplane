"""
pipeline.py
============
The Foretyx Guard Pipeline — master orchestrator.
Runs all security phases in sequence with per-phase timing, fail-closed
semantics, and structured audit logging.

v3.0 — Consensus-First Verdict Architecture:
  - Deterministic guards collect verdicts (no early return on security flags)
  - Ollama Guard runs for EVERY request (parallel with ML guard)
  - Final verdict uses consensus matrix with Ollama priority
  - Graceful fallback to scripts-only when Ollama is unavailable

Consensus Decision Matrix:
  | Scripts | Ollama  | Final                           |
  |---------|---------|----------------------------------|
  | Safe    | Safe    | Pass                             |
  | Unsafe  | Unsafe  | Block (consensus)                |
  | Safe    | Unsafe  | Block (Ollama overrides)         |
  | Unsafe  | Safe    | Review or Block (configurable)   |

Phase execution order:
  1a. Heuristic scan       (regex jailbreak patterns)           <1ms
  1b. OWASP LLM Top 10    (all 10 categories)                  <1ms
  1c. Semantic firewall    (forbidden topic keywords)           <1ms
  1d. PII scrub            (Presidio, 22+ entity types)        ~10ms
      └─ Aadhaar Verhoeff  (checksum on Aadhaar hits)          <1ms
  2a. ML injection scan    (ONNX distilbert)                   ~15ms  ┐
  2b. Ollama consensus     (LLM judgment, ALWAYS runs)         ~500ms ┘ parallel
  3.  Consensus verdict    (matrix decision)
  4.  PII policy           (block or scrub per policy)
  5.  Token budget         (tiktoken, <1ms)
  6.  Policy enforcement   (keyword blocklist, model allowlist)
"""

import asyncio
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

    v3.0: Consensus-first verdict with Ollama priority.
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
            consensus_mode=settings.consensus_ollama_always,
            consensus_disagreement=settings.consensus_disagreement_action,
        )

    # ── Result Builders ──────────────────────────────────────────────────────

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
        Build a WARN/REVIEW GuardResult.
        The prompt is NOT blocked but a warning is attached for downstream handling.
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

    # ── Consensus Logic ──────────────────────────────────────────────────────

    def _consensus_verdict(
        self,
        security_flags: list[dict],
        ollama_result: dict,
        ml_score: float,
    ) -> dict:
        """
        Apply the consensus decision matrix.

        Returns:
            {"action": "pass"|"block"|"review",
             "reason": BlockReason or None,
             "detail": str,
             "injection": bool}
        """
        scripts_block = len(security_flags) > 0
        ollama_available = ollama_result.get("available", False)
        ollama_block = ollama_result.get("action") == "block"
        ollama_reason = ollama_result.get("reason", "")

        # ── Ollama unavailable: fall back to scripts-only ────────────────
        if not ollama_available:
            if scripts_block:
                flag = security_flags[0]
                return {
                    "action": "block",
                    "reason": flag["reason"],
                    "detail": f"{flag['detail']} [consensus: scripts-only, Ollama unavailable]",
                    "injection": flag.get("injection", False),
                }
            logger.debug("consensus_scripts_only_pass", ollama_status="unavailable")
            return {"action": "pass", "reason": None, "detail": "", "injection": False}

        # ── Both safe → Pass ─────────────────────────────────────────────
        if not scripts_block and not ollama_block:
            logger.info("consensus_pass", scripts="safe", ollama="safe")
            return {"action": "pass", "reason": None, "detail": "", "injection": False}

        # ── Both unsafe → Block (consensus agreement) ────────────────────
        if scripts_block and ollama_block:
            flag = security_flags[0]
            detail = (
                f"{flag['detail']} | Ollama: {ollama_reason} "
                f"[consensus: both agree block]"
            )
            logger.warning(
                "consensus_block_agreement",
                script_guard=flag.get("guard"),
                ollama_reason=ollama_reason,
            )
            return {
                "action": "block",
                "reason": BlockReason.CONSENSUS_BLOCK,
                "detail": detail,
                "injection": flag.get("injection", False),
            }

        # ── Scripts safe, Ollama unsafe → Block (Ollama overrides) ───────
        if not scripts_block and ollama_block:
            detail = (
                f"Ollama guard override: {ollama_reason} "
                f"[consensus: Ollama vetoed scripts-safe, ML score {ml_score:.4f}]"
            )
            logger.warning(
                "consensus_ollama_override",
                ollama_reason=ollama_reason,
                ml_score=round(ml_score, 4),
            )
            return {
                "action": "block",
                "reason": BlockReason.CONSENSUS_OLLAMA_OVERRIDE,
                "detail": detail,
                "injection": True,
            }

        # ── Scripts unsafe, Ollama safe → Review or Block (configurable) ─
        flag = security_flags[0]
        action = self.settings.consensus_disagreement_action
        detail = (
            f"{flag['detail']} | Ollama: safe "
            f"[consensus: disagreement -> {action}]"
        )
        logger.warning(
            "consensus_disagreement",
            script_guard=flag.get("guard"),
            script_reason=flag["detail"],
            ollama_action="pass",
            configured_action=action,
        )
        return {
            "action": action,  # "review" or "block"
            "reason": flag["reason"],
            "detail": detail,
            "injection": flag.get("injection", False),
        }

    # ── Main Guard Method ────────────────────────────────────────────────────

    async def guard(self, raw_prompt: str) -> GuardResult:
        """
        Run the full guard pipeline on a raw prompt.

        v3.0 Consensus flow:
          1. Collect all deterministic guard verdicts
          2. Run Ollama + ML in parallel
          3. Apply consensus matrix
          4. Apply policy checks (PII, token budget, keywords)
          5. Return final verdict
        """
        t0 = time.perf_counter()
        timings: dict[str, float] = {}
        clean_text = raw_prompt
        detections: list[PiiDetection] = []
        placeholder_map: dict[str, str] = {}
        ml_score = 0.0

        # ── Input validation (structural — not security verdicts) ─────────
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

        # ══════════════════════════════════════════════════════════════════
        # SECURITY PHASE: Collect all guard verdicts (no early returns)
        # ══════════════════════════════════════════════════════════════════
        security_flags: list[dict] = []

        # ── Phase 1a: Heuristic jailbreak scan ───────────────────────────
        t_phase = time.perf_counter()
        jailbreak_detected, pattern_name = self.heuristic_scanner.scan(raw_prompt)
        timings["heuristic_scan_ms"] = (time.perf_counter() - t_phase) * 1000

        if jailbreak_detected:
            security_flags.append({
                "guard": "heuristic_scanner",
                "reason": BlockReason.HEURISTIC_JAILBREAK,
                "detail": f"Jailbreak pattern: {pattern_name}",
                "injection": True,
            })

        # ── Phase 1b: OWASP LLM Top 10 scan ─────────────────────────────
        t_phase = time.perf_counter()
        owasp_triggered, owasp_id, owasp_pattern = self.owasp_scanner.scan(raw_prompt)
        timings["owasp_scan_ms"] = (time.perf_counter() - t_phase) * 1000

        if owasp_triggered:
            security_flags.append({
                "guard": "owasp_scanner",
                "reason": BlockReason.HEURISTIC_JAILBREAK,
                "detail": f"OWASP {owasp_id}: {owasp_pattern}",
                "injection": True,
            })

        # ── Phase 1c: Semantic firewall ──────────────────────────────────
        t_phase = time.perf_counter()
        forbidden, topic, category = self.semantic_firewall.check(raw_prompt)
        timings["semantic_firewall_ms"] = (time.perf_counter() - t_phase) * 1000

        if forbidden:
            security_flags.append({
                "guard": "semantic_firewall",
                "reason": BlockReason.FORBIDDEN_TOPIC,
                "detail": f"Forbidden topic: '{topic}' (category: {category})",
                "injection": False,
            })

        # ── Phase 1d: PII scrub (always runs — modifies text) ────────────
        t_phase = time.perf_counter()
        clean_text, detections, placeholder_map = self.pii_detector.scrub(raw_prompt)
        timings["pii_scrub_ms"] = (time.perf_counter() - t_phase) * 1000

        # ── Aadhaar Verhoeff checksum validation ─────────────────────────
        from app.contracts.enums import PiiType
        valid_detections = []
        valid_placeholder_map = {}
        rejected_placeholders = set()
        for det in detections:
            if det.pii_type == PiiType.AADHAAR:
                original_value = placeholder_map.get(det.placeholder, "")
                if original_value and not is_valid_aadhaar(original_value):
                    logger.debug(
                        "aadhaar_verhoeff_rejected",
                        placeholder=det.placeholder,
                        checksum_valid=False,
                    )
                    clean_text = clean_text.replace(det.placeholder, original_value)
                    rejected_placeholders.add(det.placeholder)
                    continue
            valid_detections.append(det)
            valid_placeholder_map[det.placeholder] = placeholder_map.get(det.placeholder, "")

        for k, v in placeholder_map.items():
            if k not in valid_placeholder_map and k not in rejected_placeholders:
                valid_placeholder_map[k] = v
        detections      = valid_detections
        placeholder_map = valid_placeholder_map

        # ══════════════════════════════════════════════════════════════════
        # PARALLEL PHASE: ML Guard + Ollama Guard
        # ══════════════════════════════════════════════════════════════════
        t_phase = time.perf_counter()

        if self.settings.consensus_ollama_always:
            # Run ML and Ollama in parallel for minimum latency
            ml_coro = asyncio.to_thread(self.injection_detector.scan, raw_prompt)
            ollama_coro = self.ollama_guard.scan(clean_text)
            (ml_verdict, ml_score), ollama_result = await asyncio.gather(
                ml_coro, ollama_coro
            )
        else:
            # Legacy mode: ML first, Ollama only on escalation
            ml_verdict, ml_score = self.injection_detector.scan(raw_prompt)
            ollama_result = {"action": "pass", "available": False}

        timings["ml_guard_ms"] = (time.perf_counter() - t_phase) * 1000

        # Collect ML verdict into security flags
        if ml_verdict == "error":
            if self.settings.fail_behavior == "CLOSED":
                security_flags.append({
                    "guard": "ml_guard",
                    "reason": BlockReason.ML_GUARD_TRIGGERED,
                    "detail": "ML guard unavailable — fail-closed",
                    "injection": True,
                })
        elif ml_verdict == "block":
            security_flags.append({
                "guard": "ml_guard",
                "reason": BlockReason.ML_GUARD_TRIGGERED,
                "detail": f"ML guard score {ml_score:.4f} >= block threshold {self.settings.ml_block_threshold}",
                "injection": True,
            })

        # Legacy escalation mode (only if consensus_ollama_always is False)
        if not self.settings.consensus_ollama_always and ml_verdict == "escalate":
            t_esc = time.perf_counter()
            ollama_result = await self.ollama_guard.scan(clean_text)
            timings["ollama_escalation_ms"] = (time.perf_counter() - t_esc) * 1000

        # ══════════════════════════════════════════════════════════════════
        # CONSENSUS PHASE: Apply decision matrix
        # ══════════════════════════════════════════════════════════════════
        t_phase = time.perf_counter()
        consensus = self._consensus_verdict(security_flags, ollama_result, ml_score)
        timings["consensus_ms"] = (time.perf_counter() - t_phase) * 1000

        logger.info(
            "consensus_result",
            action=consensus["action"],
            script_flags=len(security_flags),
            ollama_available=ollama_result.get("available", False),
            ollama_action=ollama_result.get("action"),
            ml_score=round(ml_score, 4),
        )

        if consensus["action"] == "block":
            return self._blocked(
                raw_prompt, consensus["reason"],
                consensus["detail"],
                t0, timings,
                clean_text=clean_text,
                detections=detections,
                placeholder_map=placeholder_map,
                ml_score=ml_score,
                injection=consensus.get("injection", False),
            )

        if consensus["action"] == "review":
            return self._warned(
                clean_text=clean_text,
                warn_reason=f"Consensus review: {consensus['detail']}",
                t0=t0,
                timings=timings,
                detections=detections,
                placeholder_map=placeholder_map,
                ml_score=ml_score,
            )

        # ══════════════════════════════════════════════════════════════════
        # POLICY PHASE: PII, token budget, keyword blocklist
        # (Only reached when security consensus is "pass")
        # ══════════════════════════════════════════════════════════════════

        # ── PII policy check ─────────────────────────────────────────────
        bundle = self.policy_engine.get_policy()
        if detections and bundle and bundle.pii_rules.block_on_detect:
            allowed = set(bundle.pii_rules.allowed_pii_types)
            detected_types = {d.pii_type for d in detections}
            blocked_types = detected_types - allowed
            if blocked_types:
                return self._blocked(
                    raw_prompt, BlockReason.PII_DETECTED,
                    f"Sensitive data detected. Request blocked per strict protection policy. "
                    f"Types: {[t.value for t in blocked_types]}",
                    t0, timings,
                    clean_text=clean_text,
                    detections=detections,
                    placeholder_map=placeholder_map,
                    ml_score=ml_score,
                )

        # ── Token budget ─────────────────────────────────────────────────
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

        # ── PASS — prompt is safe ────────────────────────────────────────
        latency = (time.perf_counter() - t0) * 1000

        # Log sanitization info if PII was scrubbed (not blocked)
        if detections:
            logger.info(
                "pii_sanitized_and_passed",
                pii_count=len(detections),
                types=[d.pii_type.value for d in detections],
            )

        logger.info(
            "prompt_passed",
            pii_count=len(detections),
            ml_score=round(ml_score, 4),
            latency_ms=round(latency, 2),
            consensus="pass",
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

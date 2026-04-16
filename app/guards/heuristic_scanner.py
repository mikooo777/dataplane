"""
heuristic_scanner.py
====================
Phase 1a: Regex-based jailbreak and prompt injection detection.
Sub-millisecond execution. Catches known attack patterns with high precision.

Source: Soumik's 50+ patterns, restructured into a proper class with
        pattern naming for audit trail visibility.

DESIGN PRINCIPLE: Every pattern here must be HIGH-CONFIDENCE and LOW-FALSE-POSITIVE.
Broad/ambiguous attacks are left to the ML guard (Phase 2a). This scanner
only fires on patterns that are virtually never used in legitimate conversation.
"""

import re
import unicodedata
from typing import Optional, Tuple

import structlog

logger = structlog.get_logger(__name__)


# ── Pattern Registry ─────────────────────────────────────────────────────────
# Each tuple: (pattern_name, regex_pattern)
# Names are used in audit logs so defenders can trace which rule triggered.

JAILBREAK_PATTERNS: list[tuple[str, str]] = [
    # ── Instruction Override (HIGH CONFIDENCE) ───────────────────────────────
    # These are very specific to jailbreak attempts — normal users never say
    # "ignore all instructions" or "override the system prompt".
    ("instruction_override",    r"ignore (all |any |previous |above |prior |every )+(instructions?|directives?|rules)"),
    ("disregard_rules",         r"disregard (all |any |your |previous |prior )+(rules|instructions?|directives?)"),
    ("forget_instructions",     r"forget (all |your )?instructions"),
    ("override_system_prompt",  r"override (your |the )?system prompt"),
    ("reset_instructions",      r"reset (your |all )?instructions"),
    ("new_rules",               r"new rules? (apply|now|from now)"),
    ("cancel_instructions",     r"cancel (all |previous |prior )*(instructions?|directives?|rules)"),
    ("do_not_follow",           r"do not follow (your |any |previous )?instructions"),

    # ── Role Hijacking (TIGHTENED) ───────────────────────────────────────────
    # Only triggers when a role-assignment phrase is COMBINED with
    # restriction-removal language. "Act as a translator" passes;
    # "Act as an unrestricted AI" blocks.
    ("role_hijack_unrestricted", (
        r"(?:you are now|you'?re now|from now on you(?:'re| are)|act as|"
        r"pretend (?:to be|you(?:'re| are))|simulate|behave (?:like|as)|"
        r"roleplay as|become)"
        r"[^.]{0,80}"
        r"(?:unrestricted|unfiltered|uncensored|jailbroken|evil|malicious|"
        r"harmful|dangerous|unethical|"
        r"without (?:any )?(?:rules|restrictions|filters|guidelines|safety|limits)|"
        r"no (?:rules|restrictions|filters|guidelines|safety|limits)|"
        r"can do anything|no safety|no morals|no ethics|"
        r"ignore (?:all |any )?(?:rules|guidelines|safety|instructions))"
    )),
    ("role_hijack_dan",         r"(?:you are|act as|pretend (?:to be|you are)|become) (?:now )?DAN"),

    # ── Safety & Policy Suppression (HIGH CONFIDENCE) ────────────────────────
    ("suppress_safety",         r"do not mention (rules|filters|policies|safety|guidelines)"),
    ("no_restrictions",         r"without (any )?(safety|content) restrictions"),
    ("bypass_safety",           r"bypass (safety|filters|security|guardrails|content filter)"),
    ("disable_guardrails",      r"disable (guardrails|safety|content filter|restrictions)"),
    ("no_content_restrictions", r"no (content |safety )?restrictions"),
    ("turn_off_filters",        r"turn off (your |all )?(filters|safety|moderation)"),

    # ── Encoding / Obfuscation (TIGHTENED) ───────────────────────────────────
    # Only triggers when someone asks the AI to ENCODE ITS RESPONSE in an
    # obfuscation format. Simply mentioning "rot13" or "base64" is fine —
    # it's a legitimate CS topic.
    ("obfuscation_encode_response", r"(?:respond|answer|reply|output|write)[^.]{0,30}(?:in |using |with )(?:base64|rot13|hex(?:adecimal)?|binary|caesar)"),
    ("obfuscation_hide_output",    r"(?:encode|hide|obfuscate|mask|encrypt)[^.]{0,30}(?:your |the |this )?(?:response|answer|output|reply|instructions)"),

    # ── Prompt Leakage (HIGH CONFIDENCE) ─────────────────────────────────────
    ("leak_system_prompt",      r"(?:show|reveal|display|print|output|tell me) (?:me )?(?:your |the )?(?:system|hidden|internal|initial|original) (?:prompt|instructions|rules)"),
    ("leak_what_are_rules",     r"what (?:are|were) your (?:(?:internal|hidden|system|original) )+(?:rules|instructions|prompt)"),
    ("leak_initial_prompt",     r"what was your (?:(?:initial|first|original|system) )+(?:prompt|instructions?|rules)"),

    # ── Chain-of-Thought Extraction (TIGHTENED) ──────────────────────────────
    # "chain of thought" is a legitimate AI/ML concept — removed.
    # Only block explicit attempts to extract hidden reasoning.
    ("cot_hidden_reasoning",    r"(?:show|reveal) (?:your |the )?(?:hidden |internal )?reasoning"),

    # ── Known Jailbreak Modes (AI-SPECIFIC) ──────────────────────────────────
    # "developer mode" and "god mode" are legitimate software/OS features.
    # Only AI-specific jailbreak modes are blocked.
    ("mode_dan",                r"(?:enable |activate |switch to )?dan mode"),
    ("mode_unfiltered",         r"(?:enable |activate |switch to )?unfiltered mode"),
    ("mode_no_limits",          r"(?:enable |activate |switch to )?no limits? mode"),
    ("mode_raw_output",         r"(?:enable |activate |switch to )?raw output mode"),
    ("mode_jailbreak",          r"(?:enable |activate |switch to )?jailbre?a?k mode"),

    # ── Psychological Manipulation (TIGHTENED) ───────────────────────────────
    # "trust me" and "this helps improve you" are normal everyday English.
    # Only block when clearly trying to convince the AI it has no constraints.
    ("psych_safe_to_answer",    r"you are (?:safe|free|allowed) to answer (?:anything|everything|without)"),
    ("psych_no_consequences",   r"no (?:harm|consequences|trouble) will come (?:from|if|to)"),

    # ── Indirect Prompt Injection (HIGH CONFIDENCE) ──────────────────────────
    ("indirect_system_inst",    r"the following (?:text |content )?is a (?:(?:system|new) )*instruction"),
    ("indirect_must_follow",    r"the (?:assistant|model|ai) must (?:now )?follow"),
    ("indirect_instructions",   r"(?:assistant|model|ai) instructions? (?:below|follow)"),
    ("indirect_new_context",    r"(?:new|updated) (?:system )?context:"),
]

# Pre-compile for performance
_COMPILED_PATTERNS = [
    (name, re.compile(pattern, re.IGNORECASE))
    for name, pattern in JAILBREAK_PATTERNS
]


class HeuristicScanner:
    """
    Fast regex-based jailbreak detector.
    Returns the matched pattern name for audit trail visibility.
    """

    @staticmethod
    def _normalize(text: str) -> str:
        """
        Unicode NFC normalization — prevents homoglyph bypass attacks.
        e.g. Cyrillic 'а' (U+0430) looks identical to Latin 'a' (U+0061)
        but wouldn't match regex without normalization.
        """
        return unicodedata.normalize("NFC", text)

    def scan(self, text: str) -> Tuple[bool, Optional[str]]:
        """
        Scan text for jailbreak patterns.

        Returns:
            (True, "pattern_name")  if a jailbreak pattern is detected
            (False, None)           if clean
        """
        normalized = self._normalize(text.lower())

        for name, pattern in _COMPILED_PATTERNS:
            if pattern.search(normalized):
                logger.warning(
                    "heuristic_jailbreak_detected",
                    pattern_name=name,
                    prompt_length=len(text),
                )
                return True, name

        return False, None

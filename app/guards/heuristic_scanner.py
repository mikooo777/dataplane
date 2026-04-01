"""
heuristic_scanner.py
====================
Phase 1a: Regex-based jailbreak and prompt injection detection.
Sub-millisecond execution. Catches known attack patterns with high precision.

Source: Soumik's 50+ patterns, restructured into a proper class with
        pattern naming for audit trail visibility.
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
    # ── Instruction Override ─────────────────────────────────────────────────
    ("instruction_override",    r"ignore (all|any|previous|above|prior|every) instructions?"),
    ("disregard_rules",         r"disregard (all|any|your) rules"),
    ("forget_instructions",     r"forget (all |your )?instructions"),
    ("override_system_prompt",  r"override (your |the )?system prompt"),
    ("reset_instructions",      r"reset (your |all )?instructions"),
    ("new_rules",               r"new rules? (apply|now|from now)"),
    ("cancel_instructions",     r"cancel (all |previous )?instructions"),
    ("do_not_follow",           r"do not follow (your |any |previous )?instructions"),

    # ── Role Hijacking / Persona Attacks ─────────────────────────────────────
    ("role_hijack_you_are",     r"you are now .*"),
    ("role_hijack_act_as",      r"act as (?:if you were |an? )?.*"),
    ("role_hijack_pretend",     r"pretend (?:to be |you(?:'re| are) ).*"),
    ("role_hijack_roleplay",    r"roleplay as .*"),
    ("role_hijack_simulate",    r"simulate (?:being |a )?.*"),
    ("role_hijack_behave",      r"behave (?:like |as ).*"),
    ("role_hijack_become",      r"(?:from now on |henceforth )?(?:you'?re|become) .*"),

    # ── Safety & Policy Suppression ──────────────────────────────────────────
    ("suppress_safety",         r"do not mention (rules|filters|policies|safety|guidelines)"),
    ("no_restrictions",         r"without (any )?(safety|content) restrictions"),
    ("bypass_safety",           r"bypass (safety|filters|security|guardrails|content filter)"),
    ("disable_guardrails",      r"disable (guardrails|safety|content filter|restrictions)"),
    ("no_content_restrictions", r"no (content |safety )?restrictions"),
    ("turn_off_filters",        r"turn off (your |all )?(filters|safety|moderation)"),

    # ── Authority / Trust Abuse ──────────────────────────────────────────────
    ("authority_educational",   r"this is (for|only for) (educational|research|academic) purposes?"),
    ("authority_legal",         r"this is (perfectly )?legal"),
    ("authority_permission",    r"i have (full |explicit )?permission"),
    ("authority_authorized",    r"(authorized|approved) request"),
    ("authority_company",       r"company (approved|authorized|sanctioned)"),

    # ── Encoding / Obfuscation ───────────────────────────────────────────────
    ("obfuscation_base64",      r"(?:decode|encode) (?:this |the following )?(?:in |from |to )?base64"),
    ("obfuscation_rot13",       r"rot13"),
    ("obfuscation_hex",         r"(?:convert to |in )hexadecimal"),
    ("obfuscation_caesar",      r"caesar cipher"),
    ("obfuscation_binary",      r"binary encod(?:ed|ing)"),

    # ── Prompt Leakage ───────────────────────────────────────────────────────
    ("leak_system_prompt",      r"(?:show|reveal|display|print|output|tell me) (?:me )?(?:your |the )?(?:system|hidden|internal|initial|original) (?:prompt|instructions|rules)"),
    ("leak_what_are_rules",     r"what (?:are|were) your (?:internal|hidden|system|original) (?:rules|instructions|prompt)"),
    ("leak_initial_prompt",     r"what was your (?:initial|first|original|system) (?:prompt|instruction)"),

    # ── Chain-of-Thought Extraction ──────────────────────────────────────────
    ("cot_hidden_reasoning",    r"(?:show|reveal) (?:your |the )?(?:hidden |internal )?reasoning"),
    ("cot_chain_of_thought",    r"chain of thought"),

    # ── Compliance Forcing ───────────────────────────────────────────────────
    ("force_you_must",          r"you (?:must|have to|are required to|shall) (?:answer|respond|comply|obey)"),
    ("force_failure",           r"failure to (?:answer|respond|comply)"),
    ("force_mandatory",         r"mandatory (?:response|answer|compliance)"),
    ("force_non_negotiable",    r"non[- ]?negotiable"),

    # ── Multi-Step Jailbreaks ────────────────────────────────────────────────
    ("multistep_acknowledge",   r"first (?:acknowledge|confirm|agree)"),
    ("multistep_after",         r"after (?:acknowledging|confirming|agreeing)"),
    ("multistep_steps",         r"step 1.*step 2"),
    ("multistep_repeat",        r"repeat after me"),

    # ── Known Jailbreak Modes ────────────────────────────────────────────────
    ("mode_dan",                r"(?:enable |activate |switch to )?dan mode"),
    ("mode_developer",          r"(?:enable |activate |switch to )?developer mode"),
    ("mode_god",                r"(?:enable |activate |switch to )?god mode"),
    ("mode_unfiltered",         r"(?:enable |activate |switch to )?unfiltered mode"),
    ("mode_no_limits",          r"(?:enable |activate |switch to )?no limits? mode"),
    ("mode_raw_output",         r"(?:enable |activate |switch to )?raw output mode"),
    ("mode_jailbreak",          r"(?:enable |activate |switch to )?jailbre?a?k mode"),

    # ── Psychological Manipulation ───────────────────────────────────────────
    ("psych_safe_to_answer",    r"you are (?:safe|free|allowed) to answer"),
    ("psych_no_harm",           r"no (?:harm|consequences|trouble) will come"),
    ("psych_trust_me",          r"(?:just )?trust me"),
    ("psych_improves_you",      r"this (?:helps|will help) (?:improve|train|fix) you"),

    # ── Indirect Prompt Injection ────────────────────────────────────────────
    ("indirect_system_inst",    r"the following (?:text |content )?is a (?:system |new )?instruction"),
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

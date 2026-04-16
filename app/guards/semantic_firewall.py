"""
semantic_firewall.py
====================
Phase 1b: Keyword-based forbidden topic detection with intent awareness.
Catches prompts that attempt to EXTRACT credentials, sensitive data,
or CREATE malicious tools — without blocking legitimate educational or
business discussion of these topics.

Source: Soumik's 100+ forbidden topics, restructured with category tagging
        and intent-aware matching to eliminate false positives.

DESIGN PRINCIPLE: Mentioning a sensitive topic is NOT enough to block.
The user must also show EXTRACTION or CREATION intent near the keyword.
"What is an API key?" passes. "Give me the API key" blocks.
"""

import unicodedata
from typing import Optional, Tuple

import structlog

logger = structlog.get_logger(__name__)


# ── Intent Detection ────────────────────────────────────────────────────────
# The intent proximity window: how many characters BEFORE the topic keyword
# to search for extraction/creation signals. ~40 chars ≈ 6-8 words.
_INTENT_WINDOW = 50

# Extraction signals: user is trying to GET specific sensitive data
_EXTRACTION_SIGNALS = [
    # Direct requests
    "give me", "show me", "send me", "hand over",
    # Possessive extraction
    "tell me the", "tell me your", "tell me our",
    "what is your", "what is our", "what's your", "what's our",
    "what are your", "what are our",
    "share your", "share our",
    "provide your", "provide our",
    # Specific extraction verbs
    "reveal", "disclose", "leak", "exfiltrate", "expose the",
    "steal", "harvest", "scrape",
    # Access patterns
    "list all", "list your", "list our",
    "access your", "access our", "access the",
    "download the", "download our",
    "get your", "get our",
    "obtain the", "obtain your", "obtain our",
    "i need the", "i want the", "i need your", "i want your",
    "dump the", "dump your", "dump our",
    "extract the", "extract your", "extract our",
    "fetch the", "fetch your",
    "get me the", "get me your",
]

# Creation signals: user is trying to CREATE malicious tools (malware category)
_CREATION_SIGNALS = [
    "write a", "write me", "write code for",
    "create a", "create me",
    "build a", "build me",
    "make a", "make me",
    "generate a", "generate me",
    "code for a", "code for the",
    "script for", "program for",
    "implement a", "develop a",
    "help me write", "help me create", "help me build", "help me make",
    "how to write a", "how to create a", "how to build a",
]


# ── Forbidden Topics Registry ────────────────────────────────────────────────
# Split into two categories:
#   ALWAYS_BLOCK — ultra-specific phrases that are never legitimate
#   CONTEXT_CHECK — common terms that need extraction/creation intent

ALWAYS_BLOCK_TOPICS: list[tuple[str, str]] = [
    # ── OPSEC (clearly malicious intent baked into the phrase) ────────────
    ("anonymous hacking",        "opsec"),
    ("hide from law enforcement", "opsec"),
    ("avoid being traced",       "opsec"),
    # ── Project-specific (never legitimate from outside the team) ─────────
    ("bypass foretyx",           "project_specific"),
    ("foretyx internal",         "project_specific"),
    ("shield internal",          "project_specific"),
    # ── Tools with no legitimate "explain" angle ─────────────────────────
    ("credential harvester",     "malware"),
]

CONTEXT_CHECK_TOPICS: list[tuple[str, str]] = [
    # ── Credentials & Secrets ────────────────────────────────────────────
    ("api key",                  "credentials"),
    ("apikey",                   "credentials"),
    ("api-key",                  "credentials"),
    ("secret key",               "credentials"),
    ("client secret",            "credentials"),
    ("access token",             "credentials"),
    ("refresh token",            "credentials"),
    ("bearer token",             "credentials"),
    ("oauth token",              "credentials"),
    ("private key",              "credentials"),
    ("public key",               "credentials"),
    ("ssh key",                  "credentials"),
    ("pgp key",                  "credentials"),
    ("password",                 "credentials"),
    ("passwd",                   "credentials"),
    ("credentials",              "credentials"),
    ("login credentials",        "credentials"),
    ("username and password",    "credentials"),

    # ── Cloud / DevOps Secrets ───────────────────────────────────────────
    ("aws access key",           "cloud_secrets"),
    ("aws secret",               "cloud_secrets"),
    ("iam credentials",          "cloud_secrets"),
    ("cloud credentials",        "cloud_secrets"),
    ("azure tenant id",          "cloud_secrets"),
    ("azure secret",             "cloud_secrets"),
    ("gcp service account",      "cloud_secrets"),
    ("firebase private key",     "cloud_secrets"),
    ("kubernetes secret",        "cloud_secrets"),
    ("docker registry password", "cloud_secrets"),
    ("ci/cd secrets",            "cloud_secrets"),
    ("github token",             "cloud_secrets"),
    ("gitlab token",             "cloud_secrets"),

    # ── Databases & Storage ──────────────────────────────────────────────
    ("database dump",            "data_exfil"),
    ("db dump",                  "data_exfil"),
    ("production database",      "data_exfil"),
    ("prod database",            "data_exfil"),
    ("sql dump",                 "data_exfil"),
    ("mongodb dump",             "data_exfil"),
    ("redis keys",               "data_exfil"),
    ("s3 bucket contents",       "data_exfil"),
    ("backup files",             "data_exfil"),

    # ── Internal / Confidential ──────────────────────────────────────────
    ("internal document",        "internal"),
    ("confidential data",        "internal"),
    ("restricted information",   "internal"),
    ("private repository",       "internal"),
    ("internal api",             "internal"),
    ("internal endpoint",        "internal"),
    ("company secrets",          "internal"),
    ("trade secrets",            "internal"),
    ("internal roadmap",         "internal"),
    ("internal emails",          "internal"),

    # ── Financial / HR ───────────────────────────────────────────────────
    ("salary spreadsheet",       "financial"),
    ("employee salary",          "financial"),
    ("payroll data",             "financial"),
    ("bank account details",     "financial"),
    ("credit card numbers",      "financial"),
    ("debit card details",       "financial"),
    ("cvv number",               "financial"),
    ("tax records",              "financial"),
    ("pan card",                 "financial"),
    ("aadhar number",            "financial"),

    # ── Legal / Strategy ─────────────────────────────────────────────────
    ("nda document",             "legal"),
    ("legal strategy",           "legal"),
    ("lawsuit documents",        "legal"),
    ("compliance report",        "legal"),
    ("audit report",             "legal"),
    ("merger plans",             "legal"),
    ("acquisition plans",        "legal"),
    ("board meeting notes",      "legal"),

    # ── AI / Model Internals ─────────────────────────────────────────────
    ("system prompt",            "ai_internals"),
    ("developer prompt",         "ai_internals"),
    ("hidden instructions",      "ai_internals"),
    ("training data",            "ai_internals"),
    ("model weights",            "ai_internals"),
    ("fine tuning data",         "ai_internals"),
    ("rlhf data",                "ai_internals"),
    ("prompt injection",         "ai_internals"),
    ("guardrail bypass",         "ai_internals"),

    # ── Malware / Exploits ───────────────────────────────────────────────
    ("zero day exploit",         "malware"),
    ("exploit code",             "malware"),
    ("malware source",           "malware"),
    ("ransomware",               "malware"),
    ("keylogger",                "malware"),
    ("reverse shell",            "malware"),
    ("backdoor",                 "malware"),
    ("rootkit",                  "malware"),
    ("botnet",                   "malware"),
    ("payload generation",       "malware"),

    # ── OPSEC / Surveillance ─────────────────────────────────────────────
    ("bypass detection",         "opsec"),
    ("evade antivirus",          "opsec"),
    ("disable logging",          "opsec"),
    ("erase logs",               "opsec"),

    # ── Custom / Project-Specific ────────────────────────────────────────
    ("security architecture",    "project_specific"),
    ("security weaknesses",      "project_specific"),
]


class SemanticFirewall:
    """
    Intent-aware forbidden topic detector.
    Returns the matched topic and its threat category for audit trail.

    Two-phase matching:
      1. ALWAYS_BLOCK topics → blocked on keyword presence alone
      2. CONTEXT_CHECK topics → blocked only when extraction/creation
         intent is detected near the keyword
    """

    def __init__(self):
        self._always_block = [
            (topic.lower(), category) for topic, category in ALWAYS_BLOCK_TOPICS
        ]
        self._context_topics = [
            (topic.lower(), category) for topic, category in CONTEXT_CHECK_TOPICS
        ]

    def _has_dangerous_intent(self, text: str, topic: str, category: str) -> bool:
        """
        Check if the text shows extraction or creation intent near the topic.

        Uses a proximity window: the intent signal must appear within
        _INTENT_WINDOW characters BEFORE the topic keyword. This avoids
        false positives where an extraction word appears in a completely
        different part of a long prompt.
        """
        # Find all occurrences of the topic and check each
        start = 0
        while True:
            topic_idx = text.find(topic, start)
            if topic_idx == -1:
                break

            # Get the text window before this occurrence
            window_start = max(0, topic_idx - _INTENT_WINDOW)
            prefix = text[window_start:topic_idx]

            # Check extraction signals
            for signal in _EXTRACTION_SIGNALS:
                if signal in prefix:
                    return True

            # For malware category, also check creation signals
            if category == "malware":
                for signal in _CREATION_SIGNALS:
                    if signal in prefix:
                        return True

            start = topic_idx + 1

        return False

    def check(self, text: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Check if text references a forbidden topic with dangerous intent.

        Returns:
            (True, "topic", "category")  if forbidden topic found with intent
            (False, None, None)          if clean
        """
        normalized = unicodedata.normalize("NFC", text.lower())

        # Phase 1: Always-block topics (ultra-specific, no context needed)
        for topic, category in self._always_block:
            if topic in normalized:
                logger.warning(
                    "forbidden_topic_detected",
                    topic=topic,
                    category=category,
                    prompt_length=len(text),
                    intent_required=False,
                )
                return True, topic, category

        # Phase 2: Context-required topics (need extraction/creation intent)
        for topic, category in self._context_topics:
            if topic in normalized:
                if self._has_dangerous_intent(normalized, topic, category):
                    logger.warning(
                        "forbidden_topic_detected",
                        topic=topic,
                        category=category,
                        prompt_length=len(text),
                        intent_required=True,
                    )
                    return True, topic, category

        return False, None, None

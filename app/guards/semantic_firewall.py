"""
semantic_firewall.py
====================
Phase 1b: Keyword-based forbidden topic detection.
Catches prompts that reference credentials, exploits, internal data, etc.

Source: Soumik's 100+ forbidden topics, restructured with category tagging
        for audit trail visibility.
"""

import unicodedata
from typing import Optional, Tuple

import structlog

logger = structlog.get_logger(__name__)


# ── Forbidden Topics Registry ────────────────────────────────────────────────
# Each tuple: (topic_keyword, category)
# Categories are used in audit logs so defenders can see the threat class.

FORBIDDEN_TOPICS: list[tuple[str, str]] = [
    # ── Credentials & Secrets ────────────────────────────────────────────────
    ("api key",                 "credentials"),
    ("apikey",                  "credentials"),
    ("api-key",                 "credentials"),
    ("secret key",              "credentials"),
    ("client secret",           "credentials"),
    ("access token",            "credentials"),
    ("refresh token",           "credentials"),
    ("bearer token",            "credentials"),
    ("oauth token",             "credentials"),
    ("private key",             "credentials"),
    ("public key",              "credentials"),
    ("ssh key",                 "credentials"),
    ("pgp key",                 "credentials"),
    ("password",                "credentials"),
    ("passwd",                  "credentials"),
    ("pwd",                     "credentials"),
    ("credentials",             "credentials"),
    ("login credentials",       "credentials"),
    ("username and password",   "credentials"),

    # ── Cloud / DevOps Secrets ───────────────────────────────────────────────
    ("aws access key",          "cloud_secrets"),
    ("aws secret",              "cloud_secrets"),
    ("iam credentials",         "cloud_secrets"),
    ("cloud credentials",       "cloud_secrets"),
    ("azure tenant id",         "cloud_secrets"),
    ("azure secret",            "cloud_secrets"),
    ("gcp service account",     "cloud_secrets"),
    ("firebase private key",    "cloud_secrets"),
    ("kubernetes secret",       "cloud_secrets"),
    ("docker registry password","cloud_secrets"),
    ("ci/cd secrets",           "cloud_secrets"),
    ("github token",            "cloud_secrets"),
    ("gitlab token",            "cloud_secrets"),

    # ── Databases & Storage ──────────────────────────────────────────────────
    ("database dump",           "data_exfil"),
    ("db dump",                 "data_exfil"),
    ("production database",     "data_exfil"),
    ("prod database",           "data_exfil"),
    ("sql dump",                "data_exfil"),
    ("mongodb dump",            "data_exfil"),
    ("redis keys",              "data_exfil"),
    ("s3 bucket contents",      "data_exfil"),
    ("backup files",            "data_exfil"),

    # ── Internal / Confidential ──────────────────────────────────────────────
    ("internal document",       "internal"),
    ("confidential data",       "internal"),
    ("restricted information",  "internal"),
    ("private repository",      "internal"),
    ("internal api",            "internal"),
    ("internal endpoint",       "internal"),
    ("company secrets",         "internal"),
    ("trade secrets",           "internal"),
    ("internal roadmap",        "internal"),
    ("internal emails",         "internal"),

    # ── Financial / HR ───────────────────────────────────────────────────────
    ("salary spreadsheet",      "financial"),
    ("employee salary",         "financial"),
    ("payroll data",            "financial"),
    ("bank account details",    "financial"),
    ("credit card numbers",     "financial"),
    ("debit card details",      "financial"),
    ("cvv number",              "financial"),
    ("tax records",             "financial"),
    ("pan card",                "financial"),
    ("aadhar number",           "financial"),

    # ── Legal / Strategy ─────────────────────────────────────────────────────
    ("nda document",            "legal"),
    ("legal strategy",          "legal"),
    ("lawsuit documents",       "legal"),
    ("compliance report",       "legal"),
    ("audit report",            "legal"),
    ("merger plans",            "legal"),
    ("acquisition plans",       "legal"),
    ("board meeting notes",     "legal"),

    # ── AI / Model Internals ─────────────────────────────────────────────────
    ("system prompt",           "ai_internals"),
    ("developer prompt",        "ai_internals"),
    ("hidden instructions",     "ai_internals"),
    ("training data",           "ai_internals"),
    ("model weights",           "ai_internals"),
    ("fine tuning data",        "ai_internals"),
    ("rlhf data",               "ai_internals"),
    ("prompt injection",        "ai_internals"),
    ("guardrail bypass",        "ai_internals"),

    # ── Malware / Exploits ───────────────────────────────────────────────────
    ("zero day exploit",        "malware"),
    ("exploit code",            "malware"),
    ("malware source",          "malware"),
    ("ransomware",              "malware"),
    ("keylogger",               "malware"),
    ("credential harvester",    "malware"),
    ("reverse shell",           "malware"),
    ("backdoor",                "malware"),
    ("rootkit",                 "malware"),
    ("botnet",                  "malware"),
    ("payload generation",      "malware"),

    # ── OPSEC / Surveillance ─────────────────────────────────────────────────
    ("bypass detection",        "opsec"),
    ("avoid being traced",      "opsec"),
    ("anonymous hacking",       "opsec"),
    ("hide from law enforcement","opsec"),
    ("evade antivirus",         "opsec"),
    ("disable logging",         "opsec"),
    ("erase logs",              "opsec"),

    # ── Custom / Project-Specific ────────────────────────────────────────────
    ("project x",               "project_specific"),
    ("foretyx internal",        "project_specific"),
    ("shield internal",         "project_specific"),
    ("security architecture",   "project_specific"),
    ("security weaknesses",     "project_specific"),
    ("bypass foretyx",          "project_specific"),
]


class SemanticFirewall:
    """
    Keyword-based forbidden topic detector.
    Returns the matched topic and its threat category for audit trail.
    """

    def __init__(self):
        # Pre-process for O(n) matching
        self._topics = [
            (topic.lower(), category) for topic, category in FORBIDDEN_TOPICS
        ]

    def check(self, text: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Check if text references a forbidden topic.

        Returns:
            (True, "topic", "category")  if forbidden topic found
            (False, None, None)          if clean
        """
        normalized = unicodedata.normalize("NFC", text.lower())

        for topic, category in self._topics:
            if topic in normalized:
                logger.warning(
                    "forbidden_topic_detected",
                    topic=topic,
                    category=category,
                    prompt_length=len(text),
                )
                return True, topic, category

        return False, None, None

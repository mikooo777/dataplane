"""
pii_detector.py
===============
Phase 1c: PII detection and scrubbing using Microsoft Presidio.
15+ entity types including India-specific (Aadhaar, PAN, IFSC, GST, etc.),
global (email, phone, credit card), and credential patterns (API keys, passwords).

Source: Soham's enhanced detector with overlap resolution and indexed placeholders.

Features:
  - Custom recognizers for all Indian government IDs
  - API key patterns (OpenAI, AWS, Bearer tokens)
  - Password detection
  - Crypto wallet detection (BTC, ETH)
  - Overlap resolution: highest confidence wins
  - Indexed placeholders: <<EMAIL_ADDRESS_1>>, <<EMAIL_ADDRESS_2>> — never collide
"""

from typing import Tuple

import structlog
from presidio_analyzer import (
    AnalyzerEngine,
    RecognizerRegistry,
    PatternRecognizer,
    Pattern,
)
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.predefined_recognizers import (
    EmailRecognizer,
    PhoneRecognizer,
    CreditCardRecognizer,
    IpRecognizer,
    IbanRecognizer,
    UsSsnRecognizer,
)

from app.contracts.enums import PiiType
from app.contracts.guard import PiiDetection

logger = structlog.get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Custom Recognizers — India-Specific
# ═══════════════════════════════════════════════════════════════════════════════

class AadhaarRecognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(
            supported_entity="AADHAAR",
            patterns=[Pattern("AADHAAR", r"\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b", 0.85)],
            context=["aadhaar", "aadhar", "uid", "unique identification"],
        )

class PanRecognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(
            supported_entity="PAN",
            patterns=[Pattern("PAN", r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b", 0.9)],
            context=["pan", "income tax", "permanent account", "tax"],
        )

class InMobileRecognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(
            supported_entity="IN_MOBILE",
            patterns=[Pattern("IN_MOBILE", r"\b(\+91[\-\s]?)?[6-9]\d{9}", 0.75)],
            context=["mobile", "phone", "contact", "whatsapp", "call", "number"],
        )

class InVoterIdRecognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(
            supported_entity="IN_VOTER_ID",
            patterns=[Pattern("IN_VOTER_ID", r"\b[A-Z]{3}[0-9]{7}\b", 0.8)],
            context=["voter", "election", "voter id", "epic"],
        )

class InPassportRecognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(
            supported_entity="IN_PASSPORT",
            patterns=[Pattern("IN_PASSPORT", r"\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b", 0.85)],
            context=["passport", "travel document"],
        )

class InDrivingLicenseRecognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(
            supported_entity="IN_DRIVING_LICENSE",
            patterns=[Pattern("IN_DL", r"\b[A-Z]{2}[0-9]{2}[A-Z]{1,2}[0-9]{4,7}\b", 0.75)],
            context=["driving license", "dl", "licence", "driving"],
        )

class InBankAccountRecognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(
            supported_entity="IN_BANK_ACCOUNT",
            patterns=[Pattern("IN_BANK_ACCOUNT", r"\b[0-9]{9,18}\b", 0.6)],
            context=["account number", "bank account", "savings account", "current account"],
        )

class InIfscRecognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(
            supported_entity="IN_IFSC",
            patterns=[Pattern("IN_IFSC", r"\b[A-Z]{4}0[A-Z0-9]{6}\b", 0.9)],
            context=["ifsc", "bank", "transfer", "neft", "rtgs", "imps"],
        )

class InGstRecognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(
            supported_entity="IN_GST",
            patterns=[Pattern("IN_GST", r"\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}\b", 0.95)],
            context=["gst", "gstin", "tax", "goods and services"],
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Custom Recognizers — Credentials & Secrets
# ═══════════════════════════════════════════════════════════════════════════════

class ApiKeyRecognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(
            supported_entity="API_KEY",
            patterns=[
                Pattern("OPENAI_KEY",      r"\bsk-[A-Za-z0-9]{32,}\b", 0.99),
                Pattern("AWS_KEY",         r"\bAKIA[0-9A-Z]{16}\b", 0.99),
                Pattern("BEARER_TOKEN",    r"[Bb]earer\s+[A-Za-z0-9\-_\.]{20,}", 0.85),
                Pattern("API_KEY_GENERIC", r"(?i)api[-_]?key[\s:=]+['\"]?([A-Za-z0-9\-_]{20,})['\"]?", 0.8),
            ],
            context=["api", "key", "token", "secret", "bearer", "authorization"],
        )

class PasswordRecognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(
            supported_entity="PASSWORD",
            patterns=[
                Pattern("PASSWORD_IS", r"(?i)password\s+is\s+['\"]?(\S{6,})['\"]?", 0.8),
                Pattern("PASSWORD_EQ", r"(?i)password[\s:=]+['\"]?(\S{6,})['\"]?", 0.8),
                Pattern("PASSWD",      r"(?i)passwd[\s:=]+['\"]?(\S{6,})['\"]?", 0.8),
            ],
            context=["password", "passwd", "credentials", "login"],
        )

class CryptoWalletRecognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(
            supported_entity="CRYPTO_WALLET",
            patterns=[
                Pattern("BTC_WALLET", r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", 0.75),
                Pattern("ETH_WALLET", r"\b0x[a-fA-F0-9]{40}\b", 0.85),
            ],
            context=["wallet", "bitcoin", "ethereum", "crypto", "address"],
        )

class DateOfBirthRecognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(
            supported_entity="DATE_OF_BIRTH",
            patterns=[
                Pattern("DOB_SLASH", r"\b(0?[1-9]|[12][0-9]|3[01])[\/\-](0?[1-9]|1[012])[\/\-](19|20)\d\d\b", 0.7),
                Pattern("DOB_TEXT",  r"(?i)(born|dob|date of birth|birth date)[\s:]+\w+\s+\d{1,2},?\s+\d{4}", 0.8),
            ],
            context=["born", "dob", "date of birth", "birth", "age"],
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Main PII Detector
# ═══════════════════════════════════════════════════════════════════════════════

class PiiDetector:
    """
    Enhanced PII detector powered by Microsoft Presidio.
    15+ entity types with overlap resolution and indexed placeholders.
    """

    def __init__(self):
        # Configure spaCy NLP engine
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        })
        nlp_engine = provider.create_engine()

        # Build custom registry with all recognizers
        registry = RecognizerRegistry()
        for recognizer in [
            # Global (Presidio built-ins)
            EmailRecognizer(),
            PhoneRecognizer(),
            CreditCardRecognizer(),
            IpRecognizer(),
            IbanRecognizer(),
            UsSsnRecognizer(),
            # India-specific
            AadhaarRecognizer(),
            PanRecognizer(),
            InMobileRecognizer(),
            InVoterIdRecognizer(),
            InPassportRecognizer(),
            InDrivingLicenseRecognizer(),
            InBankAccountRecognizer(),
            InIfscRecognizer(),
            InGstRecognizer(),
            # Credentials & Secrets
            ApiKeyRecognizer(),
            PasswordRecognizer(),
            CryptoWalletRecognizer(),
            DateOfBirthRecognizer(),
        ]:
            registry.add_recognizer(recognizer)

        self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine, registry=registry)
        logger.info("pii_detector_initialized", recognizer_count=len(registry.recognizers))

    def scrub(self, text: str) -> Tuple[str, list[PiiDetection], dict[str, str]]:
        """
        Detect and scrub PII from text.

        Returns:
            (clean_text, detections, placeholder_map)
            - clean_text:      text with PII replaced by <<ENTITY_N>> placeholders
            - detections:      list of PiiDetection objects for audit
            - placeholder_map: {placeholder: original_value} for rehydration
        """
        results = self.analyzer.analyze(text=text, language="en")

        # ── Overlap resolution: keep highest confidence for overlapping spans ──
        results = sorted(results, key=lambda x: x.score, reverse=True)
        filtered = []
        for r in results:
            overlap = any(
                r.start < existing.end and r.end > existing.start
                for existing in filtered
            )
            if not overlap:
                filtered.append(r)

        # ── Sort descending by position so replacements don't shift indices ──
        results = sorted(filtered, key=lambda x: x.start, reverse=True)

        counters: dict[str, int] = {}
        placeholder_map: dict[str, str] = {}
        detections: list[PiiDetection] = []

        for r in results:
            entity = r.entity_type
            counters[entity] = counters.get(entity, 0) + 1
            placeholder = f"<<{entity}_{counters[entity]}>>"
            original = text[r.start:r.end]
            placeholder_map[placeholder] = original
            text = text[:r.start] + placeholder + text[r.end:]

            # Map to our PiiType enum (skip unknown entities gracefully)
            try:
                pii_type = PiiType(entity)
            except ValueError:
                # Presidio detected a type not in our enum — still scrub, just log
                logger.debug("unknown_pii_type_scrubbed", entity_type=entity)
                continue

            detections.append(PiiDetection(
                pii_type=pii_type,
                placeholder=placeholder,
                char_start=r.start,
                char_end=r.end,
                confidence=r.score,
            ))

        if detections:
            logger.info(
                "pii_scrubbed",
                count=len(detections),
                types=[d.pii_type.value for d in detections],
            )

        return text, detections, placeholder_map

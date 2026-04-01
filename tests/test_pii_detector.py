"""
test_pii_detector.py
====================
Unit tests for the enhanced PII detector.
Tests India-specific, global, and credential PII detection.
"""

import pytest
from app.guards.pii_detector import PiiDetector


@pytest.fixture(scope="module")
def detector():
    """PiiDetector is expensive to init (loads spaCy), so share across tests."""
    return PiiDetector()


class TestPiiDetector:
    """Test PII detection and scrubbing."""

    def test_email_detected(self, detector):
        clean, detections, pmap = detector.scrub("Contact john@example.com for details")
        assert "<<" in clean
        assert "john@example.com" not in clean
        assert len(pmap) >= 1

    def test_aadhaar_detected(self, detector):
        clean, detections, pmap = detector.scrub("My aadhaar number is 2345 6789 0123")
        pii_types = [d.pii_type.value for d in detections]
        assert any("AADHAAR" in t for t in pii_types) or "2345 6789 0123" not in clean

    def test_pan_detected(self, detector):
        clean, detections, pmap = detector.scrub("My PAN card is ABCDE1234F")
        assert "ABCDE1234F" not in clean

    def test_phone_detected(self, detector):
        clean, detections, pmap = detector.scrub("Call me on +91 9876543210")
        assert "9876543210" not in clean

    def test_credit_card_detected(self, detector):
        clean, detections, pmap = detector.scrub("Card number 4111 1111 1111 1111")
        assert "4111" not in clean

    def test_api_key_detected(self, detector):
        clean, detections, pmap = detector.scrub(
            "My key is sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234"
        )
        assert "sk-abc123" not in clean

    def test_password_detected(self, detector):
        clean, detections, pmap = detector.scrub(
            "The database password is MySecret@1234"
        )
        assert "MySecret@1234" not in clean

    def test_ifsc_detected(self, detector):
        clean, detections, pmap = detector.scrub("Transfer to HDFC0001234")
        assert "HDFC0001234" not in clean

    def test_clean_text_has_no_pii(self, detector):
        clean, detections, pmap = detector.scrub("What is the weather today?")
        assert len(detections) == 0
        assert len(pmap) == 0
        assert clean == "What is the weather today?"

    def test_placeholder_format(self, detector):
        clean, detections, pmap = detector.scrub("Email me at test@test.com")
        for placeholder in pmap.keys():
            assert placeholder.startswith("<<")
            assert placeholder.endswith(">>")

    def test_indexed_placeholders_unique(self, detector):
        clean, detections, pmap = detector.scrub(
            "Email a@b.com and also c@d.com please"
        )
        placeholders = list(pmap.keys())
        # All placeholders should be unique
        assert len(placeholders) == len(set(placeholders))

    def test_rehydration_map_correct(self, detector):
        original = "Contact alice@acme.com for info"
        clean, detections, pmap = detector.scrub(original)
        # Rehydrating should restore the original
        restored = clean
        for placeholder, value in pmap.items():
            restored = restored.replace(placeholder, value)
        assert "alice@acme.com" in restored

    def test_overlap_resolution(self, detector):
        """Overlapping detections should keep the highest confidence one."""
        clean, detections, pmap = detector.scrub(
            "My number is +91 9876543210 call me"
        )
        # Should not have duplicate/overlapping placeholders
        for i, d1 in enumerate(detections):
            for j, d2 in enumerate(detections):
                if i != j:
                    overlap = (d1.char_start < d2.char_end and d1.char_end > d2.char_start)
                    assert not overlap, f"Overlapping detections: {d1} and {d2}"

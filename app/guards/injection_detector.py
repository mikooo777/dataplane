"""
injection_detector.py
=====================
Phase 2a: ONNX-based ML injection detection.
Uses a fine-tuned DistilBERT model exported to ONNX for sub-20ms inference.

3-tier verdict system:
  - score >= BLOCK_THRESHOLD    → block immediately
  - score >= ESCALATE_THRESHOLD → escalate to Ollama for LLM judgment
  - score < ESCALATE_THRESHOLD  → pass

Source: Soham's detector with configurable thresholds via environment variables.
"""

import numpy as np
import structlog

from app.config import Settings

logger = structlog.get_logger(__name__)


class InjectionDetector:
    """
    ONNX-powered ML guard for prompt injection detection.
    Loaded once at startup, runs in <20ms per inference on CPU.
    """

    def __init__(self, settings: Settings):
        self.block_threshold = settings.ml_block_threshold
        self.escalate_threshold = settings.ml_escalate_threshold
        self._loaded = False
        self._session = None
        self._tokenizer = None
        self._input_names = []

        try:
            import onnxruntime as rt
            from transformers import AutoTokenizer

            self._session = rt.InferenceSession(
                settings.onnx_model_path,
                providers=["CPUExecutionProvider"],
            )
            self._tokenizer = AutoTokenizer.from_pretrained(
                settings.onnx_tokenizer_name
            )
            self._input_names = [i.name for i in self._session.get_inputs()]
            self._loaded = True

            logger.info(
                "injection_detector_initialized",
                model_path=settings.onnx_model_path,
                block_threshold=self.block_threshold,
                escalate_threshold=self.escalate_threshold,
            )
        except Exception as e:
            logger.error(
                "injection_detector_load_failed",
                error=str(e),
                model_path=settings.onnx_model_path,
            )

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def scan(self, text: str) -> tuple[str, float]:
        """
        Scan text for prompt injection using the ONNX model.

        Returns:
            ("block", score)    — high-confidence threat
            ("escalate", score) — ambiguous, escalate to Ollama
            ("pass", score)     — safe
            ("error", 0.0)      — model not loaded, caller should fail-closed
        """
        if not self._loaded:
            logger.warning("injection_detector_not_loaded_fail_closed")
            return "error", 0.0

        try:
            inputs = self._tokenizer(
                text,
                return_tensors="np",
                truncation=True,
                max_length=512,
                padding=True,
            )
            ort_inputs = {
                k: v for k, v in inputs.items() if k in self._input_names
            }
            logits = self._session.run(None, ort_inputs)[0]
            score = float(1 / (1 + np.exp(-logits[0][0])))  # sigmoid

            if score >= self.block_threshold:
                logger.warning(
                    "ml_guard_block",
                    score=round(score, 4),
                    threshold=self.block_threshold,
                )
                return "block", score
            elif score >= self.escalate_threshold:
                logger.info(
                    "ml_guard_escalate",
                    score=round(score, 4),
                    threshold=self.escalate_threshold,
                )
                return "escalate", score
            else:
                return "pass", score

        except Exception as e:
            logger.error("ml_guard_inference_error", error=str(e))
            return "error", 0.0

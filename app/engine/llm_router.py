"""
llm_router.py
=============
Multi-model LLM router with retry logic and exponential backoff.
Only receives clean (scrubbed) text — never the raw prompt.
"""

import asyncio

import google.generativeai as genai
import structlog

from app.config import Settings

logger = structlog.get_logger(__name__)

SUPPORTED_MODELS = {
    "gemini-2.5-pro":   "gemini-2.5-pro",
    "gemini-2.0-flash": "gemini-2.0-flash",
    "gemini-1.5-pro":   "gemini-1.5-pro",
    "gemini-1.5-flash": "gemini-1.5-flash",
}


class LLMRouter:
    """
    Routes clean prompts to the appropriate Gemini model.
    Includes retry with exponential backoff on transient failures.
    """

    def __init__(self, settings: Settings):
        genai.configure(api_key=settings.gemini_api_key)
        self._default_model = settings.default_llm_model
        self._timeout = settings.llm_timeout_seconds
        self._max_retries = settings.llm_max_retries
        logger.info(
            "llm_router_initialized",
            default_model=self._default_model,
            supported_models=list(SUPPORTED_MODELS.keys()),
        )

    async def call(self, clean_prompt: str, model_requested: str) -> str:
        """
        Forward the scrubbed clean_prompt to Gemini.
        Never receives raw prompt — only clean_text from GuardResult.

        Returns raw LLM response text (may contain placeholders to rehydrate).
        """
        model_name = SUPPORTED_MODELS.get(model_requested, self._default_model)

        last_error = None
        for attempt in range(self._max_retries + 1):
            try:
                model = genai.GenerativeModel(model_name)
                response = await asyncio.to_thread(
                    model.generate_content, clean_prompt
                )
                logger.info(
                    "llm_call_success",
                    model=model_name,
                    attempt=attempt + 1,
                    response_length=len(response.text) if response.text else 0,
                )
                return response.text

            except Exception as e:
                last_error = e
                if attempt < self._max_retries:
                    wait = 2 ** attempt  # exponential backoff: 1s, 2s, 4s
                    logger.warning(
                        "llm_call_retry",
                        model=model_name,
                        attempt=attempt + 1,
                        max_retries=self._max_retries,
                        error=str(e),
                        retry_in_seconds=wait,
                    )
                    await asyncio.sleep(wait)

        logger.error(
            "llm_call_failed",
            model=model_name,
            attempts=self._max_retries + 1,
            error=str(last_error),
        )
        raise RuntimeError(
            f"LLM call failed after {self._max_retries + 1} attempts: {last_error}"
        )

    def is_model_allowed(self, model_requested: str, allowed_models: list[str]) -> bool:
        """Check if the requested model is in the org's allowlist."""
        return model_requested in allowed_models

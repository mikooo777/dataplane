"""
token_budget.py
===============
Prompt token budget enforcement using tiktoken (Guide Section 3.4).

Why tiktoken?
  - The estimate used previously (word_count * 1.3) is inaccurate for:
    * Code (many tokens per word)
    * Unicode / CJK / Devanagari text
    * Structured data (JSON, CSV)
  - tiktoken uses the exact BPE tokenizer that OpenAI/Gemini-compatible models use
  - We target the cl100k_base encoding (GPT-4 / Gemini-compatible)

Integration:
  - Called in the guard pipeline (Phase 3) BEFORE sending to LLM
  - Replaces the old `word_count * 1.3` estimate
  - Hard limit is set per PolicyBundle.max_prompt_tokens
"""

import structlog

logger = structlog.get_logger(__name__)

# cl100k_base is the BPE encoding used by GPT-4 and is a good
# approximation for Gemini's tokenizer as well.
_ENCODING_NAME = "cl100k_base"
_encoder = None


def _get_encoder():
    """Lazy-load tiktoken encoder — avoids startup cost if not used."""
    global _encoder
    if _encoder is None:
        try:
            import tiktoken
            _encoder = tiktoken.get_encoding(_ENCODING_NAME)
            logger.info(
                "tiktoken_encoder_loaded",
                encoding=_ENCODING_NAME,
            )
        except ImportError:
            logger.warning(
                "tiktoken_not_installed",
                action="falling_back_to_word_estimate",
                install="pip install tiktoken",
            )
        except Exception as e:
            logger.warning(
                "tiktoken_load_failed",
                error=str(e),
                action="falling_back_to_word_estimate",
            )
    return _encoder


def count_tokens(text: str) -> int:
    """
    Count the number of tokens in the given text.

    Uses tiktoken (cl100k_base) if available, otherwise falls back to
    the word-count approximation (word_count * 1.3) used in legacy code.

    Args:
        text: The text to count tokens for.

    Returns:
        Integer token count estimate.
    """
    encoder = _get_encoder()
    if encoder is not None:
        try:
            token_ids = encoder.encode(text)
            return len(token_ids)
        except Exception as e:
            logger.warning("tiktoken_encode_error", error=str(e))
            # Fall through to estimate

    # Fallback: word-based estimate
    return int(len(text.split()) * 1.3)


def check_token_budget(text: str, max_tokens: int) -> tuple[bool, int]:
    """
    Check whether the text fits within the token budget.

    Args:
        text:       The prompt text to check.
        max_tokens: Maximum allowed tokens (from PolicyBundle).

    Returns:
        (within_budget, actual_count)
        - within_budget: True if actual_count <= max_tokens
        - actual_count:  The measured token count
    """
    actual = count_tokens(text)
    within = actual <= max_tokens

    if not within:
        logger.warning(
            "token_budget_exceeded",
            actual_tokens=actual,
            max_tokens=max_tokens,
            excess=actual - max_tokens,
        )
    else:
        logger.debug(
            "token_budget_ok",
            actual_tokens=actual,
            max_tokens=max_tokens,
            headroom=max_tokens - actual,
        )

    return within, actual

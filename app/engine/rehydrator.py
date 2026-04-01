"""
rehydrator.py
=============
Restores original PII values into the LLM response.
The placeholder_map was held in memory on-device the entire time —
PII never touches the LLM or the network.
"""

import structlog

logger = structlog.get_logger(__name__)


class Rehydrator:
    """
    Replaces <<ENTITY_N>> tokens in the LLM response with original values.
    """

    @staticmethod
    def restore(llm_response: str, placeholder_map: dict[str, str]) -> str:
        """
        Restore PII into the LLM response.

        Args:
            llm_response:   The raw LLM response (may contain <<ENTITY_N>> tokens)
            placeholder_map: {placeholder: original_value}

        Returns:
            The response with all placeholders replaced by original values.
        """
        if not placeholder_map:
            return llm_response

        result = llm_response
        restored_count = 0

        for placeholder, original in placeholder_map.items():
            if placeholder in result:
                result = result.replace(placeholder, original)
                restored_count += 1

        if restored_count > 0:
            logger.info(
                "pii_rehydrated",
                placeholders_restored=restored_count,
                total_placeholders=len(placeholder_map),
            )

        return result

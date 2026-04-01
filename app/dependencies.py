"""
dependencies.py
===============
FastAPI dependency injection helpers.
Used by route handlers to access shared services.
"""

from functools import lru_cache

from app.config import Settings


@lru_cache()
def get_settings() -> Settings:
    """Cached settings singleton — loaded once from environment."""
    return Settings()

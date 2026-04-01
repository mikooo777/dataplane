"""
security.py
===========
Security utilities: API key validation, secure headers, input sanitization.
"""

import re
from typing import Optional
from fastapi import HTTPException, status, Header


class SecurityValidator:
    """Centralized security validation and constants."""
    
    # API key format: simple bearer token validation
    BEARER_PREFIX = "Bearer "
    MIN_API_KEY_LENGTH = 32
    
    # Input validation
    MAX_PROMPT_LENGTH = 50000
    MIN_PROMPT_LENGTH = 1
    
    # IP validation (basic check for X-Forwarded-For)
    IP_PATTERN = re.compile(
        r'^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$'  # IPv4 or IPv6
    )
    
    @staticmethod
    def validate_api_key(auth_header: Optional[str] = Header(None)) -> str:
        """
        Validate API key from Authorization header.
        Returns the key on success, raises HTTPException on failure.
        """
        if not auth_header:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Authorization header",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        if not auth_header.startswith(SecurityValidator.BEARER_PREFIX):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Authorization header format. Use 'Bearer <token>'",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        token = auth_header[len(SecurityValidator.BEARER_PREFIX):]
        
        if len(token) < SecurityValidator.MIN_API_KEY_LENGTH:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        return token
    
    @staticmethod
    def validate_prompt_length(prompt: str, max_length: int = MAX_PROMPT_LENGTH) -> str:
        """Validate prompt length and return it if valid."""
        if not prompt or len(prompt) < SecurityValidator.MIN_PROMPT_LENGTH:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Prompt must be at least {SecurityValidator.MIN_PROMPT_LENGTH} character(s)",
            )
        
        if len(prompt) > max_length:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Prompt exceeds maximum length of {max_length} characters",
            )
        
        return prompt
    
    @staticmethod
    def validate_client_ip(client_ip: str) -> bool:
        """Validate IP address format to prevent injection."""
        if not client_ip or client_ip == "unknown":
            return False
        
        # Check if it looks like a valid IP
        return bool(SecurityValidator.IP_PATTERN.match(client_ip))
    
    @staticmethod
    def sanitize_error_message(error: Exception) -> str:
        """
        Return a safe error message that doesn't expose internal details.
        """
        error_type = type(error).__name__
        
        # Only expose category, not actual error message
        if isinstance(error, TimeoutError):
            return "Request timeout - please try again"
        elif isinstance(error, ValueError):
            return "Invalid request parameters"
        elif isinstance(error, ConnectionError):
            return "Service unavailable - please try again later"
        else:
            return "An error occurred processing your request"


def get_secure_headers() -> dict[str, str]:
    """
    Return secure HTTP headers to prevent common attacks.
    """
    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'none'",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    }

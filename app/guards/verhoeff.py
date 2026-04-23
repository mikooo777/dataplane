"""
verhoeff.py
===========
Verhoeff checksum algorithm for Aadhaar number validation (Guide Section 2.2).

The Unique Identification Authority of India (UIDAI) uses the Verhoeff algorithm
(a dihedral group D5 checksum) as the check digit for all 12-digit Aadhaar numbers.

Reference:
  https://en.wikipedia.org/wiki/Verhoeff_algorithm
  UIDAI Technical Specification — Aadhaar Authentication API v2.5

Usage:
    from app.guards.verhoeff import is_valid_aadhaar
    is_valid_aadhaar("2345 6789 0123")  # -> True/False
"""

# Multiplication table (d5 group)
_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

# Permutation table
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

# Inverse table
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def _verhoeff_checksum(number_str: str) -> int:
    """
    Compute the Verhoeff checksum of a digit string.
    Returns 0 if the number (including check digit) is valid.
    """
    c = 0
    digits = [int(d) for d in reversed(number_str)]
    for i, digit in enumerate(digits):
        c = _D[c][_P[i % 8][digit]]
    return c


def is_valid_aadhaar(aadhaar: str) -> bool:
    """
    Validate an Aadhaar number using the Verhoeff algorithm.

    Args:
        aadhaar: Raw Aadhaar string — spaces and hyphens are stripped.
                 Must be exactly 12 digits after stripping.

    Returns:
        True  — format is valid AND checksum passes
        False — invalid format OR checksum fails

    Examples:
        is_valid_aadhaar("2345 6789 0123") -> depends on checksum
        is_valid_aadhaar("1234 5678 9012") -> False (starts with 1, but checksum may also fail)
    """
    # Strip whitespace and hyphens
    digits_only = aadhaar.replace(" ", "").replace("-", "")

    # Must be 12 digits
    if not digits_only.isdigit() or len(digits_only) != 12:
        return False

    # First digit must be 2–9 (UIDAI rule — 0 and 1 are reserved)
    if digits_only[0] in ("0", "1"):
        return False

    # Verhoeff checksum on all 12 digits must equal 0
    return _verhoeff_checksum(digits_only) == 0


def generate_check_digit(partial_aadhaar: str) -> int:
    """
    Given the first 11 digits of an Aadhaar, compute the correct check digit.

    Args:
        partial_aadhaar: 11-digit string (spaces/hyphens stripped)

    Returns:
        The check digit (0–9) that makes the 12-digit number Verhoeff-valid.
    """
    digits_only = partial_aadhaar.replace(" ", "").replace("-", "")
    if not digits_only.isdigit() or len(digits_only) != 11:
        raise ValueError(f"Expected 11 digits, got: {partial_aadhaar!r}")

    # Try each possible check digit
    for check in range(10):
        if _verhoeff_checksum(digits_only + str(check)) == 0:
            return check
    raise RuntimeError("No valid Verhoeff check digit found — this should never happen")

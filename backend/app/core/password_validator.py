"""
Password validation module with configurable complexity requirements.

For home lab use, defaults are permissive. Operators can tighten requirements
via environment variables:
  - PASSWORD_MIN_LENGTH (default: 8)
  - PASSWORD_REQUIRE_UPPERCASE (default: false)
  - PASSWORD_REQUIRE_LOWERCASE (default: false)
  - PASSWORD_REQUIRE_DIGIT (default: false)
  - PASSWORD_REQUIRE_SPECIAL (default: false)
"""

import re
from typing import List, Tuple

from app.core.config import settings


def validate_password(password: str) -> Tuple[bool, List[str]]:
    """
    Validate password against configured complexity requirements.
    
    Args:
        password: The password to validate
        
    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors: List[str] = []
    
    # Minimum length check
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        errors.append(f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long")
    
    # Uppercase check
    if settings.PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    
    # Lowercase check
    if settings.PASSWORD_REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    
    # Digit check
    if settings.PASSWORD_REQUIRE_DIGIT and not re.search(r'\d', password):
        errors.append("Password must contain at least one digit")
    
    # Special character check
    if settings.PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>\-_=+\[\]\\;\'`~]', password):
        errors.append("Password must contain at least one special character")
    
    return len(errors) == 0, errors


def get_password_requirements() -> dict:
    """
    Get the current password requirements configuration.
    
    Returns:
        Dictionary describing current password requirements
    """
    return {
        "min_length": settings.PASSWORD_MIN_LENGTH,
        "require_uppercase": settings.PASSWORD_REQUIRE_UPPERCASE,
        "require_lowercase": settings.PASSWORD_REQUIRE_LOWERCASE,
        "require_digit": settings.PASSWORD_REQUIRE_DIGIT,
        "require_special": settings.PASSWORD_REQUIRE_SPECIAL,
    }


def get_password_requirements_message() -> str:
    """
    Get a human-readable message describing password requirements.
    
    Returns:
        String describing what the password must contain
    """
    requirements = []
    requirements.append(f"at least {settings.PASSWORD_MIN_LENGTH} characters")
    
    if settings.PASSWORD_REQUIRE_UPPERCASE:
        requirements.append("an uppercase letter")
    if settings.PASSWORD_REQUIRE_LOWERCASE:
        requirements.append("a lowercase letter")
    if settings.PASSWORD_REQUIRE_DIGIT:
        requirements.append("a digit")
    if settings.PASSWORD_REQUIRE_SPECIAL:
        requirements.append("a special character")
    
    if len(requirements) == 1:
        return f"Password must be {requirements[0]}"
    
    return "Password must contain " + ", ".join(requirements[:-1]) + f", and {requirements[-1]}"

"""
Validation module for the fasthtml_admin library.
"""

import re
from typing import Any, Callable, Dict, List, Tuple, Union

# Constants for password validation
MIN_PASSWORD_LENGTH = 8
PASSWORD_PATTERNS = {
    "lowercase letters": r"[a-z]",
    "uppercase letters": r"[A-Z]",
    "numbers": r"\d",
    "special characters": r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]"
}

def validate_password_strength(password: str) -> tuple[int, list[str]]:
    """
    Validate password strength and return a score (0-100) and list of issues.
    
    Args:
        password: The password to validate
        
    Returns:
        A tuple containing a score (0-100) and a list of issues
    """
    if not password:
        return 0, ["Password is required"]
    
    issues = []
    score = 0
    
    # Length check (up to 40 points)
    length_score = min(len(password) * 3, 40)
    score += length_score
    if len(password) < MIN_PASSWORD_LENGTH:
        issues.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    
    # Character type checks (15 points each)
    for pattern_name, pattern in PASSWORD_PATTERNS.items():
        if re.search(pattern, password):
            score += 15
        else:
            issues.append(f"Missing {pattern_name}")
    
    # Common patterns check
    common_patterns = [
        r'123', r'abc', r'qwerty', r'admin', r'password',
        r'([a-zA-Z0-9])\1{2,}'  # Three or more repeated characters
    ]
    for pattern in common_patterns:
        if re.search(pattern, password.lower()):
            score = max(0, score - 20)
            issues.append("Contains common pattern")
            break
    
    return score, issues

def validate_email_format(email: str) -> tuple[bool, str]:
    """
    Validate email format and return (is_valid, message).
    
    Args:
        email: The email to validate
        
    Returns:
        A tuple containing a boolean indicating if the email is valid and a message
    """
    if not email:
        return False, "Email is required"
    
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return False, "Invalid email format"
    
    return True, "Email format is valid"

def validate_passwords_match(password: str, confirm_password: str) -> tuple[bool, str]:
    """
    Validate that passwords match and return (match, message).
    
    Args:
        password: The first password
        confirm_password: The second password to compare
        
    Returns:
        A tuple containing a boolean indicating if the passwords match and a message
    """
    if not password or not confirm_password:
        return False, "Both passwords are required"
    
    if password != confirm_password:
        return False, "Passwords do not match"
    
    return True, "Passwords match"

class ValidationManager:
    """
    Manages validation functions for the fasthtml_admin library.
    
    This class allows for registering custom validators and using them
    throughout the application.
    """
    
    def __init__(self):
        """Initialize the ValidationManager with default validators."""
        self.validators: Dict[str, Callable] = {
            "password_strength": validate_password_strength,
            "email_format": validate_email_format,
            "passwords_match": validate_passwords_match
        }
    
    def register_validator(self, name: str, validator: Callable) -> None:
        """
        Register a validator function.
        
        Args:
            name: The name of the validator
            validator: The validator function
        """
        self.validators[name] = validator
    
    def validate(self, validator_name: str, *args, **kwargs) -> Any:
        """
        Validate using the specified validator.
        
        Args:
            validator_name: The name of the validator to use
            *args: Arguments to pass to the validator
            **kwargs: Keyword arguments to pass to the validator
            
        Returns:
            The result of the validator function
            
        Raises:
            ValueError: If the validator is not found
        """
        validator = self.validators.get(validator_name)
        if not validator:
            raise ValueError(f"Validator '{validator_name}' not found")
        
        return validator(*args, **kwargs)

# Global validation manager instance
validation_manager = ValidationManager()

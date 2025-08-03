"""
FastHTML Admin Library

A library for user authentication, admin management, database administration, and validation.
"""

from .auth import UserManager, auth_before, get_current_user
from .models import UserCredential, ConfirmToken
from .models.peewee_adaptator import UserCredentialPeewee, ConfirmTokenPeewee
from .admin import AdminManager
from .utils import generate_token, hash_password, verify_password
from .validation import (
    validate_password_strength,
    validate_email_format,
    validate_passwords_match,
    ValidationManager,
    validation_manager
)
from .oauth import OAuthManager

__all__ = [
    'UserManager',
    'UserCredential',
    'UserCredentialPeewee',
    'ConfirmToken',
    'ConfirmTokenPeewee',
    'AdminManager',
    'generate_token',
    'hash_password',
    'verify_password',
    'auth_before',
    'get_current_user',
    'validate_password_strength',
    'validate_email_format',
    'validate_passwords_match',
    'ValidationManager',
    'validation_manager',
    'OAuthManager',
]

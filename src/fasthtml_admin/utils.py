"""
Utility functions for the fasthtml_admin library.
"""

import secrets
import bcrypt
from datetime import datetime, timedelta

def generate_token(length=32):
    """Generate a secure random token."""
    return secrets.token_urlsafe(length)

def hash_password(password):
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed_password):
    """Verify a password against a hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

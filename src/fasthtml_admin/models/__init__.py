from dataclasses import dataclass
from datetime import datetime
from typing import Optional


class BaseConfirmToken:
    pass


@dataclass
class ConfirmToken(BaseConfirmToken):
    """
    Token for email confirmation.
    This class is designed to work with FastHTML's database system.
    """
    token: str  # Primary key
    email: str
    expiry: datetime
    is_used: bool = False


class BaseUserCredentials:
    pass


@dataclass
class UserCredential(BaseUserCredentials):
    """
    Basic user credential class for authentication.
    This class is designed to work with FastHTML's database system.

    This class can be extended by creating a subclass with additional fields
    before passing it to the UserManager constructor.
    """
    email: str  # Primary key
    id: str
    pwd: str  # Hashed password
    created_at: datetime
    is_confirmed: bool = False
    is_admin: bool = False
    last_login: Optional[datetime] = None


class BaseSystemSetting:
    pass


@dataclass
class SystemSetting(BaseSystemSetting):
    """
    System setting class for storing configuration values.
    This class is designed to work with FastHTML's database system.
    """
    key: str  # Primary key
    value: str
    updated_at: datetime = None

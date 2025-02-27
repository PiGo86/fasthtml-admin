"""
Authentication module for the fasthtml_admin library.
"""

import secrets
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Optional
from fasthtml.common import database

from .utils import hash_password, verify_password, generate_token

@dataclass
class ConfirmToken:
    """
    Token for email confirmation.
    This class is designed to work with FastHTML's database system.
    """
    token: str  # Primary key
    email: str
    expiry: datetime
    is_used: bool = False

@dataclass
class UserCredential:
    """
    Basic user credential class for authentication.
    This class is designed to work with FastHTML's database system.
    """
    email: str  # Primary key
    id: str
    pwd: str  # Hashed password
    created_at: datetime
    is_confirmed: bool = False
    is_admin: bool = False
    last_login: Optional[datetime] = None

class UserManager:
    """
    Manages user authentication, registration, and related operations.
    """
    def __init__(self, db_or_store, table_name="user_credentials"):
        """
        Initialize the UserManager with either a FastHTML database or a dictionary store.
        
        Args:
            db_or_store: Either a FastHTML database instance or a dictionary for storing users
            table_name: Name of the table to use if db_or_store is a FastHTML database
        """
        self.is_db = hasattr(db_or_store, 'create')
        
        if self.is_db:
            # Using FastHTML database
            self.db = db_or_store
            self.users = self.db.create(UserCredential, pk="email", name=table_name)
        else:
            # Using dictionary store
            self.users = db_or_store
    
    def create_user(self, email, password):
        """
        Create a new user with the given email and password.
        
        Args:
            email: User's email address
            password: Plain text password to be hashed
            
        Returns:
            The created user object
            
        Raises:
            ValueError: If a user with the given email already exists
        """
        # Check if user already exists
        try:
            if self.is_db:
                existing_user = self.users[email]
            else:
                existing_user = self.users.get(email)
            
            if existing_user:
                raise ValueError(f"User with email {email} already exists")
        except (KeyError, IndexError, Exception) as e:
            # User doesn't exist, continue with creation
            # NotFoundError is raised by FastHTML database when a record is not found
            if not isinstance(e, Exception) or "NotFoundError" not in str(type(e)):
                raise  # Re-raise if it's not a NotFoundError
            pass
        
        # Create new user
        user_id = secrets.token_hex(16)
        hashed_pwd = hash_password(password)
        
        user_data = {
            "id": user_id,
            "email": email,
            "pwd": hashed_pwd,
            "created_at": datetime.now(),
            "is_confirmed": False,
            "is_admin": False
        }
        
        if self.is_db:
            # Insert into FastHTML database
            user = self.users.insert(user_data)
        else:
            # Insert into dictionary store
            self.users[email] = user_data
            user = user_data
            
        return user
    
    def authenticate_user(self, email, password):
        """
        Authenticate a user with the given email and password.
        
        Args:
            email: User's email address
            password: Plain text password to verify
            
        Returns:
            The user object if authentication succeeds, None otherwise
        """
        try:
            if self.is_db:
                user = self.users[email]
            else:
                user = self.users.get(email)
                
            if not user:
                return None
                
            # Verify password
            if verify_password(password, user.pwd if self.is_db else user["pwd"]):
                # Update last login time
                if self.is_db:
                    user.last_login = datetime.now()
                    self.users.update(user)
                else:
                    user["last_login"] = datetime.now()
                return user
            
            return None
        except (KeyError, IndexError, Exception) as e:
            # NotFoundError is raised by FastHTML database when a record is not found
            if not isinstance(e, Exception) or "NotFoundError" not in str(type(e)):
                raise  # Re-raise if it's not a NotFoundError or KeyError/IndexError
            return None
    
    def confirm_user(self, email):
        """
        Mark a user as confirmed.
        
        Args:
            email: User's email address
            
        Returns:
            True if the user was confirmed, False otherwise
        """
        try:
            if self.is_db:
                user = self.users[email]
                user.is_confirmed = True
                self.users.update(user)
            else:
                user = self.users.get(email)
                if user:
                    user["is_confirmed"] = True
            return True
        except (KeyError, IndexError, Exception) as e:
            # NotFoundError is raised by FastHTML database when a record is not found
            if not isinstance(e, Exception) or "NotFoundError" not in str(type(e)):
                raise  # Re-raise if it's not a NotFoundError or KeyError/IndexError
            return False
    
    def generate_confirmation_token(self, email, token_store=None, expiry_days=7):
        """
        Generate a confirmation token for the given email.
        
        Args:
            email: User's email address
            token_store: Optional store for tokens (FastHTML database or dict)
            expiry_days: Number of days until the token expires
            
        Returns:
            The generated token
        """
        token = generate_token()
        
        if token_store:
            from datetime import timedelta
            expiry = datetime.now() + timedelta(days=expiry_days)
            
            token_data = {
                "token": token,
                "email": email,
                "expiry": expiry,
                "is_used": False
            }
            
            if hasattr(token_store, 'insert'):
                # FastHTML database
                token_store.insert(token_data)
            else:
                # Dictionary store
                token_store[token] = token_data
                
        return token

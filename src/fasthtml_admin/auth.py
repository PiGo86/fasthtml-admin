"""
Authentication module for the fasthtml_admin library.
"""

import secrets
from datetime import datetime, timedelta
from enum import StrEnum, auto
from importlib import import_module
from importlib.util import find_spec
from typing import Optional, Tuple, List

from fasthtml.common import RedirectResponse, NotFoundError, Database, Table
import apswutils as apsw

from .models import UserCredential
from .utils import hash_password, verify_password, generate_token
from .validation import validation_manager


class Storage(StrEnum):
    FAST_HTML = auto()
    PEEWEE = auto()
    DICT = auto()


# Optionally import peewee as pw
if find_spec('peewee') is not None:
    pw = import_module('peewee')
else:
    pw = None

def auth_before(req, sess, user_manager, login_url='/login', public_paths=None, 
               admin_manager=None, maintenance_url='/maintenance'):
    """
    Authentication Beforeware function for FastHTML.
    If maintenance mode is enabled, redirects non-admin users to maintenance page.
    Checks if user is authenticated and redirects to login page if not.
    
    Args:
        req: The request object
        sess: The session object
        user_manager: An instance of UserManager
        login_url: URL to redirect to if not authenticated
        public_paths: List of paths that don't require authentication
        admin_manager: Optional AdminManager instance to check for maintenance mode
        maintenance_url: URL to redirect to if in maintenance mode
        
    Returns:
        RedirectResponse if not authenticated or in maintenance mode, None otherwise
    """
    if public_paths is None:
        public_paths = ['/', '/login', '/register', '/confirm-email']
    
    # Always allow access to maintenance page and login page
    if maintenance_url and maintenance_url not in public_paths:
        public_paths.append(maintenance_url)
    if login_url and login_url not in public_paths:
        public_paths.append(login_url)
    
    path = req.url.path
    
    # Check for maintenance mode first (before authentication)
    if admin_manager and admin_manager.is_maintenance_mode():
        # Always allow access to maintenance page and login page
        if path == maintenance_url or path == login_url:
            pass
        # Check if user is authenticated and is an admin
        elif 'user_id' in sess:
            user_id = sess.get('user_id')
            # Find user to check if they're an admin
            users = user_manager.users
            is_admin = False

            match user_manager.storage:

                case Storage.FAST_HTML: # Using FastHTML database
                    for user in users():
                        if user.id == user_id:
                            is_admin = user.is_admin
                            break

                case Storage.PEEWEE: # Using peewee database
                    user = user_manager.users.get_or_none(id=user_id)
                    if user is not None:
                        is_admin = user.is_admin

                case _: # Using dictionary store
                    for user in users.values():
                        if user["id"] == user_id:
                            is_admin = user.get("is_admin", False)
                            break
            
            # If admin, allow access and store auth info
            if is_admin:
                req.scope['auth'] = user_id
            else:
                # Non-admin user, redirect to maintenance page
                return RedirectResponse(maintenance_url, status_code=303)
        else:
            # Not logged in, redirect to maintenance page
            return RedirectResponse(maintenance_url, status_code=303)
    
    # Skip authentication for public routes
    if (path in public_paths
            or any(path.startswith(p) for p in public_paths if p.endswith('/') and p != '/')):
        return
    
    # Check if user is authenticated
    if 'user_id' not in sess:
        return RedirectResponse(login_url, status_code=303)
    
    # Store auth info in request scope for easy access
    user_id = sess.get('user_id')
    req.scope['auth'] = user_id
    return


def get_current_user(sess, user_manager):
    """
    Get the current user from the session.
    
    Args:
        sess: The session object
        user_manager: An instance of UserManager
        
    Returns:
        The user object or None if not logged in
    """
    user_id = sess.get('user_id')
    if not user_id:
        return None
    
    # Find user by ID
    users = user_manager.users

    match user_manager.storage:

        case Storage.FAST_HTML: # Using FastHTML database
            for user in users():
                if user.id == user_id:
                    return user

        case Storage.PEEWEE: # Using peewee database
            user = users.get_or_none(id=user_id)
            if user is not None:
                return user

        case Storage.DICT: # Using dictionary store
            for user in users.values():
                if user["id"] == user_id:
                    return user
    return None


class UserManager:
    """
    Manages user authentication, registration, and related operations.
    """
    def __init__(self, db_or_store, user_class=UserCredential,
                 table_name="user_credentials", validation_mgr=None,
                 ):
        """
        Initialize the UserManager with either a FastHTML database, a peewee database
        or a dictionary store.
        
        Args:
            db_or_store: Either a FastHTML database instance or a dictionary for storing users
            user_class: The user class to use (default: UserCredential)
                        This can be a subclass of UserCredential with additional fields
            table_name: Name of the table to use if db_or_store is a FastHTML database
            validation_mgr: Optional ValidationManager instance for custom validation
        """
        self.user_class = user_class

        if isinstance(db_or_store, Database):
            self.is_db = True
            self.storage = Storage.FAST_HTML
            self.db = db_or_store
            self.users: apsw.Table = self.db.create(user_class,
                                                         pk="email",
                                                         name=table_name)

        elif pw is not None and isinstance(db_or_store, pw.Database):
            self.is_db = True
            self.storage = Storage.PEEWEE
            self.db = db_or_store
            self.db.create_tables([self.user_class,])
            self.users: type[pw.Model] = self.user_class

        elif isinstance(db_or_store, dict):
            self.is_db = False
            self.storage = Storage.DICT
            self.users: dict = db_or_store
            
        # Use provided validation manager or the global instance
        self.validation_manager = validation_mgr or validation_manager
    
    def validate_email(self, email: str) -> Tuple[bool, str]:
        """
        Validate email format.
        
        Args:
            email: The email to validate
            
        Returns:
            A tuple containing a boolean indicating if the email is valid and a message
        """
        return self.validation_manager.validate("email_format", email)
    
    def validate_password(self, password: str, min_score: int = 50) -> Tuple[bool, List[str]]:
        """
        Validate password strength.
        
        Args:
            password: The password to validate
            min_score: Minimum acceptable score (0-100)
            
        Returns:
            A tuple containing a boolean indicating if the password is strong enough and a list of issues
        """
        score, issues = self.validation_manager.validate("password_strength", password)
        return score >= min_score, issues
    
    def validate_passwords_match(self, password: str, confirm_password: str) -> Tuple[bool, str]:
        """
        Validate that passwords match.
        
        Args:
            password: The first password
            confirm_password: The second password to compare
            
        Returns:
            A tuple containing a boolean indicating if the passwords match and a message
        """
        return self.validation_manager.validate("passwords_match", password, confirm_password)
    
    def create_user(self, email, password, min_password_score=50,
                    validate=True, **additional_fields):
        """
        Create a new user with the given email and password.
        
        Args:
            email: User's email address
            password: Plain text password to be hashed
            min_password_score: Minimum acceptable password score (0-100)
            validate: Whether to validate email and password
            **additional_fields: Additional fields to include in the user object
                                These must match fields defined in the user_class
            
        Returns:
            The created user object
            
        Raises:
            ValueError: If validation fails or a user with the given email already exists
        """
        # Validate email and password if validation is enabled
        if validate:
            # Validate email format
            is_valid_email, email_message = self.validate_email(email)
            if not is_valid_email:
                raise ValueError(email_message)
            
            # Validate password strength
            is_strong_password, password_issues = self.validate_password(password, min_password_score)
            if not is_strong_password:
                raise ValueError(f"Password is not strong enough: {', '.join(password_issues)}")
        
        # Check if user already exists
        try:
            match self.storage:
                case Storage.FAST_HTML:
                    existing_user = self.users[email]
                case Storage.PEEWEE:
                    existing_user = self.users.get(email=email)
                case _:
                    existing_user = self.users.get(email)
            
            if existing_user:
                raise ValueError(f"User with email {email} already exists")
        except (KeyError, IndexError, NotFoundError, pw.DoesNotExist):
            # User doesn't exist, continue with creation
            # NotFoundError is raised by FastHTML database when a record is not found
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
            "is_admin": False,
            "last_login": None
        }
        
        # Add any additional fields
        user_data.update(additional_fields)

        match self.storage:
            case Storage.FAST_HTML:
                # Insert into FastHTML database
                user = self.users.insert(user_data)
            case Storage.PEEWEE:
                # Insert into peewee database
                user = self.users.create(**user_data)
            case _:
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
            
        Returns:from datetime import timedelta
            The user object if authentication succeeds, None otherwise
        """
        try:
            match self.storage:
                case Storage.FAST_HTML:
                    user = self.users[email]
                case Storage.PEEWEE:
                    user = self.users.get(email=email)
                case _:
                    user = self.users.get(email)

        except (KeyError, IndexError, NotFoundError):
            user = None

        finally:
            if not user:
                return None
                
        # Verify password
        if verify_password(password, user.pwd if self.storage != Storage.DICT else user["pwd"]):
            # Update last login time
            match self.storage:
                case Storage.FAST_HTML:
                    user.last_login = datetime.now()
                    self.users.update(user)
                case Storage.PEEWEE:
                    user.last_login = datetime.now()
                    user.save()
                case _:
                    user["last_login"] = datetime.now()

            return user

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
            match self.storage:
                case Storage.FAST_HTML:
                    user = self.users[email]
                    user.is_confirmed = True
                    self.users.update(user)
                case Storage.PEEWEE:
                    user = self.users.get(email=email)
                    user.is_confirmed = True
                    user.save()
                case _:
                    user = self.users.get(email)
                    user["is_confirmed"] = True

            return True

        except (KeyError, IndexError, NotFoundError):
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
            expiry = datetime.now() + timedelta(days=expiry_days)
            
            token_data = {
                "token": token,
                "email": email,
                "expiry": expiry,
                "is_used": False
            }

            if isinstance(token_store, apsw.Table):
                # FastHTML database
                token_store.insert(token_data)
            elif pw is not None and issubclass(token_store, pw.Model):
                # peewee database
                token_store.create(**token_data)
            else:
                # Dictionary store
                token_store[token] = token_data
                
        return token

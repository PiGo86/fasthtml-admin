"""
OAuth integration for fasthtml_admin.

This module provides classes for integrating FastHTML's OAuth support with the UserManager class.
"""

import secrets
from fasthtml.common import RedirectResponse
from fasthtml.oauth import OAuth

class OAuthManager(OAuth):
    """
    OAuth manager that integrates with UserManager.
    
    This class extends FastHTML's OAuth class to integrate with the UserManager class,
    allowing for seamless authentication with OAuth providers.
    """
    
    def __init__(self, app, client, user_manager, redir_path='/auth_redirect', 
                 login_path='/login', error_path='/error', logout_path='/logout', 
                 dashboard_path='/dashboard', skip=None, https=True, http_patterns=None):
        """
        Initialize the OAuthManager.
        
        Args:
            app: The FastHTML app
            client: The OAuth client (e.g., GitHubAppClient, GoogleAppClient)
            user_manager: An instance of UserManager
            redir_path: The path to redirect to after OAuth authentication
            login_path: The path to redirect to for login
            error_path: The path to redirect to on error
            logout_path: The path to redirect to after logout
            dashboard_path: The path to redirect to after successful authentication
            skip: List of paths to skip authentication for
            https: Whether to use HTTPS for redirect URLs
            http_patterns: Patterns to match for HTTP URLs
        """
        # Import here to avoid circular imports
        from fasthtml.oauth import http_patterns as default_http_patterns
        
        self.user_manager = user_manager
        self.dashboard_path = dashboard_path
        
        # Use default http_patterns if None is provided
        if http_patterns is None:
            http_patterns = default_http_patterns
            
        super().__init__(app, client, skip=skip, redir_path=redir_path, 
                         error_path=error_path, logout_path=logout_path, 
                         login_path=login_path, https=https, http_patterns=http_patterns)
    
    def get_auth(self, info, ident, session, state):
        """
        Process OAuth authentication and create or retrieve a user.
        
        This method is called when a user successfully authenticates with an OAuth provider.
        It creates or retrieves a user in our system based on the OAuth user info.
        
        Args:
            info: User information from the OAuth provider
            ident: Unique identifier for the user
            session: The session object
            state: Optional state passed during login
            
        Returns:
            RedirectResponse to redirect the user after authentication
        """
        # Extract email from OAuth response - different providers use different fields
        email = self._extract_email(info, ident)
        
        print(f"OAuth user authenticated: {email}")
        
        # Check if user exists in our system
        existing_user = self._find_user_by_email(email)
        
        if existing_user:
            # User exists, update session
            user_id = existing_user.id if self.user_manager.is_db else existing_user["id"]
            session['user_id'] = user_id
            print(f"Existing user logged in: {email}")
        else:
            # User doesn't exist, create a new one
            try:
                user_id = self._create_new_user(email)
                # Store user ID in session
                session['user_id'] = user_id
            except ValueError as e:
                print(f"Error creating user: {e}")
                return RedirectResponse(f'{self.login_path}?error=creation_failed', status_code=303)
        
        # Redirect to dashboard
        return RedirectResponse(self.dashboard_path, status_code=303)
    
    def _extract_email(self, info, ident):
        """
        Extract email from OAuth provider info.
        
        Different providers use different fields for email, so we try to handle common cases.
        
        Args:
            info: User information from the OAuth provider
            ident: Unique identifier for the user
            
        Returns:
            Email address or a generated email based on provider and identifier
        """
        # Try common email fields
        email = info.get('email')
        
        if not email:
            # Try to extract username/login
            username = info.get('login') or info.get('username') or info.get('name') or str(ident)
            
            # Generate an email based on the provider name and username
            provider = self.cli.__class__.__name__.lower().replace('appclient', '')
            email = f"{username}@{provider}.user"
        
        return email
    
    def _find_user_by_email(self, email):
        """
        Find a user by email in the user manager.
        
        Args:
            email: Email address to search for
            
        Returns:
            User object if found, None otherwise
        """
        if self.user_manager.is_db:
            # Using FastHTML database
            for user in self.user_manager.users():
                if user.email == email:
                    return user
            return None
        else:
            # Using dictionary store
            return self.user_manager.users.get(email)
    
    def _create_new_user(self, email):
        """
        Create a new user with the given email.
        
        Args:
            email: Email address for the new user
            
        Returns:
            User ID of the created user
            
        Raises:
            ValueError: If user creation fails
        """
        # Generate a random password for the user
        # They won't need this password since they'll log in via OAuth
        random_password = secrets.token_urlsafe(16)
        
        # Create user with email verification already confirmed
        user = self.user_manager.create_user(email, random_password, validate=False)
        
        if self.user_manager.is_db:
            # Mark user as confirmed
            user.is_confirmed = True
            self.user_manager.users.update(user)
            return user.id
        else:
            # Mark user as confirmed
            user["is_confirmed"] = True
            return user["id"]

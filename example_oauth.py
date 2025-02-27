#!/usr/bin/env python
"""
An example FAST HTML Website that demonstrates OAuth integration with fasthtml_admin.
This example shows how to:
- Set up OAuth authentication with GitHub
- Integrate OAuth with the UserManager from fasthtml_admin
- Create or retrieve users based on OAuth information
- Protect routes with authentication
"""

import os
import secrets
from datetime import datetime
from fasthtml.common import *
from fasthtml.oauth import GitHubAppClient, OAuth

# Import our library
from fasthtml_admin import (
    UserManager, 
    UserCredential, 
    AdminManager, 
    ConfirmToken, 
    auth_before, 
    get_current_user,
    OAuthManager
)

# Create a database
db_path = "data"
if not os.path.exists(db_path):
    os.makedirs(db_path)

db = database(os.path.join(db_path, "oauth_example.db"))

# Initialize UserManager with our database
user_manager = UserManager(db)

# Initialize AdminManager with our UserManager
admin_manager = AdminManager(user_manager)

# Create an OAuth client for GitHub
# In a real application, you would get these from environment variables
client_id = os.environ.get("GITHUB_CLIENT_ID")
client_secret = os.environ.get("GITHUB_CLIENT_SECRET")

if not client_id or not client_secret:
    print("WARNING: GitHub OAuth credentials not found in environment variables.")
    print("Please set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET environment variables.")
    print("For this example, we'll use placeholder values that won't work for actual authentication.")
    client_id = "your-github-client-id"
    client_secret = "your-github-client-secret"

# Create the GitHub OAuth client
github_client = GitHubAppClient(client_id, client_secret)

# No need to create a custom OAuth class anymore - we're using OAuthManager from the library

# Create a FastHTML app with session support
app, rt = fast_app(
    secret_key="your-secret-key-here",  # In production, use a secure random key
    session_cookie="session",
    max_age=3600 * 24 * 7,  # 7 days
    sess_path="/",
    same_site="lax",
    sess_https_only=False  # Set to True in production with HTTPS
)

# Initialize OAuth with our app and GitHub client
# The OAuthManager class will add its own Beforeware to the app
oauth = OAuthManager(
    app=app,
    client=github_client,
    user_manager=user_manager,
    redir_path='/auth_redirect',  # Explicitly set the redirect path
    login_path='/login',          # Explicitly set the login path
    dashboard_path='/dashboard'   # Where to redirect after successful authentication
)

# Routes
@app.get("/")
def home(session, request):
    """
    Home page that shows different content based on authentication status.
    If the user is not logged in, it shows a login button that links directly to GitHub OAuth.
    """
    user = get_current_user(session, user_manager)
    login_link = oauth.login_link(request)

    if user:
        # User is logged in
        email = user.email if user_manager.is_db else user["email"]
        
        content = Container(
            H1(f"Welcome, {email}!"),
            P("You are logged in via OAuth."),
            A("Go to Dashboard", href="/dashboard", cls="button"),
            A("Logout", href="/logout", cls="button secondary")
        )
    else:
        # User is not logged in
        content = Container(
            H1("Welcome to FastHTML OAuth Example"),
            P("This example demonstrates OAuth integration with fasthtml_admin."),
            Div(
                A("Login with GitHub", href=login_link, cls="button"),
                style="display: flex; gap: 1rem;"
            )
        )
    
    return content

@app.get("/login")
def login(request):
    """
    Login page that redirects to GitHub OAuth.
    This is a fallback in case the beforeware redirects here.
    """
    login_link = oauth.login_link(request)
    
    return Container(
        H1("Login"),
        P("Please log in using your GitHub account."),
        A("Login with GitHub", href=login_link, cls="button")
    )

@app.get("/dashboard")
def dashboard(session):
    user = get_current_user(session, user_manager)
    # The auth_before Beforeware will handle redirecting if not logged in
    
    email = user.email if user_manager.is_db else user["email"]
    
    return Container(
        H1("Dashboard"),
        P(f"Welcome to your dashboard, {email}!"),
        P("You have successfully authenticated via OAuth."),
        P("This is a protected page that only logged-in users can access."),
        A("Home", href="/", cls="button"),
        A("Logout", href="/logout", cls="button secondary")
    )

if __name__ == "__main__":
    print("\nStarting OAuth example server...")
    print("To use this example, you need to:")
    print("1. Register an OAuth app on GitHub")
    print("2. Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET environment variables")
    print("3. Set the Authorization callback URL to http://localhost:8000/auth_redirect")
    
    # Print current OAuth configuration
    print("\nCurrent OAuth configuration:")
    print(f"  Client ID: {'*****' + client_id[-4:] if client_id and client_id != 'your-github-client-id' else 'Not set'}")
    print(f"  Client Secret: {'*****' + client_secret[-4:] if client_secret and client_secret != 'your-github-client-secret' else 'Not set'}")
    print(f"  Redirect URI: http://localhost:8000/auth_redirect")
    
    # Print routes for reference
    print("\nRegistered routes:")
    for route in app.routes:
        print(f"  {route.path} - {route.methods}")
    
    print("\nRunning server at http://localhost:8000")
    serve(host="localhost", port=8000)

#!/usr/bin/env python
"""
An example FAST HTML Website that includes:
- user registration
- confirmation with a fake email function
- login
- admin user creation
- access to an admin panel
- buttons to download and upload the database
"""

import os
import secrets
from datetime import datetime, timedelta
from fasthtml.common import *

# Import our library
from fasthtml_admin import UserManager, UserCredential, AdminManager, ConfirmToken

# Create a FastHTML app
app, rt = fast_app()

# Create a database
db_path = "data"
if not os.path.exists(db_path):
    os.makedirs(db_path)

db = database(os.path.join(db_path, "example.db"))

# Create a token store for confirmation tokens
confirm_tokens = db.create(ConfirmToken, pk="token")

# Initialize UserManager with our database
user_manager = UserManager(db)

# Initialize AdminManager with our UserManager
admin_manager = AdminManager(user_manager)

# Create an admin user if environment variables are provided
admin_email = os.environ.get("ADMIN_EMAIL", "admin@example.com")
admin_password = os.environ.get("ADMIN_PASSWORD", "adminpass")
admin_manager.ensure_admin(admin_email, admin_password)

# Simple session management
sessions = {}

# Fake email sending function
def send_confirmation_email(email, token):
    """
    Simulate sending a confirmation email.
    In a real application, this would send an actual email.
    """
    print(f"Sending confirmation email to {email}")
    print(f"Confirmation link: http://localhost:8000/confirm-email/{token}")
    return True

# Helper function to check if user is logged in
def get_current_user(req):
    session_id = req.cookies.get("session_id")
    if session_id and session_id in sessions:
        user_id = sessions[session_id]
        # Find user by ID
        users = user_manager.users
        if user_manager.is_db:
            # Using FastHTML database
            for user in users():
                if user.id == user_id:
                    return user
        else:
            # Using dictionary store
            for user in users.values():
                if user["id"] == user_id:
                    return user
    return None

# Routes
@app.get("/")
def home(req):
    user = get_current_user(req)
    
    if user:
        # User is logged in
        email = user.email if user_manager.is_db else user["email"]
        is_admin = user.is_admin if user_manager.is_db else user["is_admin"]
        
        content = Container(
            H1(f"Welcome, {email}!"),
            P("You are logged in."),
            A("Go to Dashboard", href="/dashboard", cls="button"),
            A("Logout", href="/logout", cls="button secondary"),
            A("Admin Panel", href="/admin", cls="button secondary") if is_admin else None
        )
    else:
        # User is not logged in
        content = Container(
            H1("Welcome to FastHTML Admin Example"),
            P("This is an example website demonstrating the fasthtml_admin library."),
            Div(
                A("Login", href="/login", cls="button"),
                A("Register", href="/register", cls="button secondary"),
                style="display: flex; gap: 1rem;"
            )
        )
    
    return content

@app.get("/register")
def get_register(req):
    user = get_current_user(req)
    if user:
        return RedirectResponse("/")
    
    form = Form(
        H1("Register"),
        Input(name="email", type="email", placeholder="Email", required=True),
        Input(name="password", type="password", placeholder="Password", required=True),
        Input(name="confirm_password", type="password", placeholder="Confirm Password", required=True),
        Button("Register", type="submit"),
        P(A("Already have an account? Login", href="/login")),
        action="/register",
        method="post"
    )
    
    return Container(form)

@app.post("/register")
def post_register(email: str, password: str, confirm_password: str):
    if password != confirm_password:
        return Container(
            H1("Registration Failed"),
            P("Passwords do not match."),
            A("Try Again", href="/register", cls="button")
        )
    
    try:
        # Create user
        user = user_manager.create_user(email, password)
        
        # Generate confirmation token
        token = user_manager.generate_confirmation_token(email, confirm_tokens)
        
        # Send confirmation email
        send_confirmation_email(email, token)
        
        return Container(
            H1("Registration Successful"),
            P("A confirmation email has been sent to your email address."),
            P("Please check your email and click the confirmation link to activate your account."),
            P("For this example, the confirmation link is printed to the console."),
            A("Login", href="/login", cls="button")
        )
    except ValueError as e:
        return Container(
            H1("Registration Failed"),
            P(str(e)),
            A("Try Again", href="/register", cls="button")
        )

@app.get("/confirm-email/{token}")
def confirm_email(token: str):
    try:
        # Find token in database
        confirm_token = confirm_tokens[token]
        
        # Check if token is already used
        if confirm_token.is_used:
            return Container(
                H1("Confirmation Failed"),
                P("This confirmation link has already been used."),
                A("Login", href="/login", cls="button")
            )
        
        # Check if token is expired
        # Convert expiry from string to datetime if needed
        expiry = confirm_token.expiry
        if isinstance(expiry, str):
            expiry = datetime.fromisoformat(expiry)
        if expiry < datetime.now():
            return Container(
                H1("Confirmation Failed"),
                P("This confirmation link has expired."),
                A("Register Again", href="/register", cls="button")
            )
        
        # Confirm user
        user_manager.confirm_user(confirm_token.email)
        
        # Mark token as used
        confirm_token.is_used = True
        confirm_tokens.update(confirm_token)
        
        return Container(
            H1("Email Confirmed"),
            P("Your email has been confirmed. You can now login."),
            A("Login", href="/login", cls="button")
        )
    except (KeyError, IndexError, Exception) as e:
        # NotFoundError is raised by FastHTML database when a record is not found
        if not isinstance(e, Exception) or "NotFoundError" not in str(type(e)):
            # If it's not a NotFoundError, re-raise it
            if not isinstance(e, (KeyError, IndexError)):
                raise
        return Container(
            H1("Confirmation Failed"),
            P("Invalid confirmation link."),
            A("Register Again", href="/register", cls="button")
        )

@app.get("/login")
def get_login(req):
    user = get_current_user(req)
    if user:
        return RedirectResponse("/")
    
    form = Form(
        H1("Login"),
        Input(name="email", type="email", placeholder="Email", required=True),
        Input(name="password", type="password", placeholder="Password", required=True),
        Button("Login", type="submit"),
        P(A("Don't have an account? Register", href="/register")),
        action="/login",
        method="post"
    )
    
    return Container(form)

@app.post("/login")
def post_login(email: str, password: str):
    user = user_manager.authenticate_user(email, password)
    
    if not user:
        return Container(
            H1("Login Failed"),
            P("Invalid email or password."),
            A("Try Again", href="/login", cls="button")
        )
    
    # Check if user is confirmed
    is_confirmed = user.is_confirmed if user_manager.is_db else user["is_confirmed"]
    if not is_confirmed:
        return Container(
            H1("Login Failed"),
            P("Your email has not been confirmed."),
            P("Please check your email for a confirmation link."),
            A("Try Again", href="/login", cls="button")
        )
    
    # Create session
    session_id = secrets.token_urlsafe()
    user_id = user.id if user_manager.is_db else user["id"]
    sessions[session_id] = user_id
    
    # Redirect to dashboard with session cookie
    # Use status_code 303 to change the method from POST to GET
    response = RedirectResponse("/dashboard", status_code=303)
    response.set_cookie(key="session_id", value=session_id)
    
    return response

@app.get("/logout")
def logout(req):
    session_id = req.cookies.get("session_id")
    if session_id and session_id in sessions:
        del sessions[session_id]
    
    response = RedirectResponse("/")
    response.delete_cookie(key="session_id")
    
    return response

@app.get("/dashboard")
def dashboard(req):
    user = get_current_user(req)
    if not user:
        return RedirectResponse("/login")
    
    email = user.email if user_manager.is_db else user["email"]
    is_admin = user.is_admin if user_manager.is_db else user["is_admin"]
    
    return Container(
        H1("Dashboard"),
        P(f"Welcome to your dashboard, {email}!"),
        P("This is a protected page that only logged-in users can access."),
        A("Logout", href="/logout", cls="button secondary"),
        A("Admin Panel", href="/admin", cls="button secondary") if is_admin else None
    )

@app.get("/admin")
def admin_panel(req):
    user = get_current_user(req)
    if not user:
        return RedirectResponse("/login")
    
    is_admin = user.is_admin if user_manager.is_db else user["is_admin"]
    if not is_admin:
        return Container(
            H1("Access Denied"),
            P("You do not have permission to access this page."),
            A("Go to Dashboard", href="/dashboard", cls="button")
        )
    
    return Container(
        H1("Admin Panel"),
        P("Welcome to the admin panel!"),
        P("This is a protected page that only admin users can access."),
        H2("Database Management"),
        Div(
            A("Backup Database", href="/admin/backup-db", cls="button"),
            A("Download Database", href="/admin/download-db", cls="button"),
            A("Upload Database", href="/admin/upload-db", cls="button secondary"),
            style="display: flex; gap: 1rem;"
        ),
        A("Go to Dashboard", href="/dashboard", cls="button secondary"),
        A("Logout", href="/logout", cls="button secondary")
    )

@app.get("/admin/backup-db")
def backup_db(req):
    user = get_current_user(req)
    if not user:
        return RedirectResponse("/login")
    
    is_admin = user.is_admin if user_manager.is_db else user["is_admin"]
    if not is_admin:
        return Container(
            H1("Access Denied"),
            P("You do not have permission to access this page."),
            A("Go to Dashboard", href="/dashboard", cls="button")
        )
    
    try:
        backup_path = admin_manager.backup_database(os.path.join(db_path, "example.db"))
        
        return Container(
            H1("Database Backup"),
            P("Database backup created successfully."),
            P(f"Backup file: {backup_path}"),
            A("Go to Admin Panel", href="/admin", cls="button")
        )
    except Exception as e:
        return Container(
            H1("Backup Failed"),
            P(f"Error: {str(e)}"),
            A("Go to Admin Panel", href="/admin", cls="button")
        )

@app.get("/admin/download-db")
def download_db(req):
    user = get_current_user(req)
    if not user:
        return RedirectResponse("/login")
    
    is_admin = user.is_admin if user_manager.is_db else user["is_admin"]
    if not is_admin:
        return Container(
            H1("Access Denied"),
            P("You do not have permission to access this page."),
            A("Go to Dashboard", href="/dashboard", cls="button")
        )
    
    try:
        db_file_path = os.path.join(db_path, "example.db")
        
        # Check if the file exists
        if not os.path.exists(db_file_path):
            return Container(
                H1("Download Failed"),
                P("Database file not found."),
                A("Go to Admin Panel", href="/admin", cls="button")
            )
        
        # Return the file as a download
        filename = os.path.basename(db_file_path)
        return FileResponse(
            path=db_file_path,
            filename=filename,
            media_type="application/octet-stream"
        )
    except Exception as e:
        return Container(
            H1("Download Failed"),
            P(f"Error: {str(e)}"),
            A("Go to Admin Panel", href="/admin", cls="button")
        )

@app.get("/admin/upload-db")
def get_upload_db(req):
    user = get_current_user(req)
    if not user:
        return RedirectResponse("/login")
    
    is_admin = user.is_admin if user_manager.is_db else user["is_admin"]
    if not is_admin:
        return Container(
            H1("Access Denied"),
            P("You do not have permission to access this page."),
            A("Go to Dashboard", href="/dashboard", cls="button")
        )
    
    form = Form(
        H1("Upload Database"),
        P("Warning: This will replace the current database with the uploaded file."),
        Input(name="db_file", type="file", accept=".db,.bak", required=True),
        Button("Upload", type="submit"),
        A("Cancel", href="/admin", cls="button secondary"),
        action="/admin/upload-db",
        method="post",
        enctype="multipart/form-data"
    )
    
    return Container(form)

@app.post("/admin/upload-db")
async def post_upload_db(req):
    user = get_current_user(req)
    if not user:
        return RedirectResponse("/login")
    
    is_admin = user.is_admin if user_manager.is_db else user["is_admin"]
    if not is_admin:
        return Container(
            H1("Access Denied"),
            P("You do not have permission to access this page."),
            A("Go to Dashboard", href="/dashboard", cls="button")
        )
    
    try:
        form = await req.form()
        db_file = form.get("db_file")
        
        if not db_file:
            return Container(
                H1("Upload Failed"),
                P("No file selected."),
                A("Try Again", href="/admin/upload-db", cls="button")
            )
        
        # Save uploaded file to temporary location
        temp_path = os.path.join(db_path, "temp_upload.db")
        with open(temp_path, "wb") as f:
            f.write(await db_file.read())
        
        # Restore database from temporary file
        admin_manager.restore_database(os.path.join(db_path, "example.db"), temp_path)
        
        # Remove temporary file
        os.remove(temp_path)
        
        return Container(
            H1("Database Upload"),
            P("Database uploaded and restored successfully."),
            A("Go to Admin Panel", href="/admin", cls="button")
        )
    except Exception as e:
        return Container(
            H1("Upload Failed"),
            P(f"Error: {str(e)}"),
            A("Try Again", href="/admin/upload-db", cls="button")
        )

serve()

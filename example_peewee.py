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
import re
from datetime import datetime, timedelta
from fasthtml.common import *
import peewee as pw

# Import our library
from fasthtml_admin import (
    UserManager,
    UserCredentialPeewee,
    AdminManager,
    ConfirmTokenPeewee,
    auth_before,
    get_current_user,
    validation_manager,
)
from fasthtml_admin.models.peewee_adaptator import db_proxy

# Create a database
db_path = "data"
if not os.path.exists(db_path):
    os.makedirs(db_path)

db = pw.SqliteDatabase(os.path.join(db_path, "example_peewee.db"))


# Create an extended user class with additional fields
class ExtendedUser(UserCredentialPeewee):
    """
    Extended user class with additional fields.
    """
    first_name: str = ""
    last_name: str = ""
    phone: str = ""
    bio: str = ""
    profile_image: str = ""

db_proxy.initialize(db)

db.create_tables([ExtendedUser, ConfirmTokenPeewee],)

# Register a custom username validator
def validate_username(username: str) -> tuple[bool, str]:
    """
    Validate username format and return (is_valid, message).
    
    Args:
        username: The username to validate
        
    Returns:
        A tuple containing a boolean indicating if the username is valid and a message
    """
    if not username:
        return False, "Username is required"
    
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    
    if len(username) > 20:
        return False, "Username must be at most 20 characters"
    
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username must contain only letters, numbers, and underscores"
    
    return True, "Username is valid"

# Register the custom validator
validation_manager.register_validator("username", validate_username)

# Initialize UserManager with our database and extended user class
user_manager = UserManager(db, user_class=ExtendedUser)

# Initialize AdminManager with our UserManager
admin_manager = AdminManager(user_manager)

# You can enable maintenance mode by default if needed
# admin_manager.set_maintenance_mode(True)

# Create an admin user if environment variables are provided
admin_email = os.environ.get("ADMIN_EMAIL", "admin@example.com")
admin_password = os.environ.get("ADMIN_PASSWORD", "adminpass")
admin_manager.ensure_admin(admin_email, admin_password)

# Define authentication Beforeware with our specific configuration
def app_auth_before(req, sess):
    return auth_before(req, sess, user_manager, 
                      login_url='/login',
                      public_paths=['/', '/login', '/register', '/advanced-register', '/confirm-email', '/confirm-email/'],
                      admin_manager=admin_manager,
                      maintenance_url='/maintenance')

# Fake email sending function
def send_confirmation_email(email, token):
    """
    Simulate sending a confirmation email.
    In a real application, this would send an actual email.
    """
    print(f"Sending confirmation email to {email}")
    print(f"Confirmation link: http://localhost:8000/confirm-email/{token}")
    return True

# Create a FastHTML app with session support and authentication
beforeware = Beforeware(app_auth_before)
app, rt = fast_app(
    secret_key="your-secret-key-here",  # In production, use a secure random key
    before=beforeware,
    session_cookie="session",
    max_age=3600 * 24 * 7,  # 7 days
    sess_path="/",
    same_site="lax",
    sess_https_only=False  # Set to True in production with HTTPS
)

# Routes
@app.get("/")
def home(session):
    user = get_current_user(session, user_manager)
    
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
                A("Register", href="/register", cls="button"),
                A("Advanced Register", href="/advanced-register", cls="button secondary"),
                style="display: flex; gap: 1rem;"
            )
        )
    
    return content

@app.get("/register")
def get_register(session):
    user = get_current_user(session, user_manager)
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
    try:
        # Validate that passwords match
        is_match, match_message = user_manager.validate_passwords_match(password, confirm_password)
        if not is_match:
            return Container(
                H1("Registration Failed"),
                P(match_message),
                A("Try Again", href="/register", cls="button")
            )
        
        # Create user (this will validate email format and password strength)
        user = user_manager.create_user(email, password, min_password_score=50)
        
        # Generate confirmation token
        token = user_manager.generate_confirmation_token(email, ConfirmTokenPeewee)
        
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

# Advanced registration with HTMX-based validation
@app.get("/advanced-register")
def get_advanced_register(session):
    user = get_current_user(session, user_manager)
    if user:
        return RedirectResponse("/")
    
    # Create a form with HTMX validation
    form = Form(
        H1("Advanced Registration with Real-time Validation"),
        
        # Username field with HTMX validation
        Div(
            Label("Username", 
                  Input(name="username", placeholder="Username", required=True,
                        hx_post="/validate/username",
                        hx_trigger="keyup changed delay:500ms",
                        hx_target="#username-feedback")),
            Div(id="username-feedback", cls="feedback"),
            cls="form-group"
        ),
        
        # Email field with HTMX validation
        Div(
            Label("Email", 
                  Input(name="email", type="email", placeholder="Email", required=True,
                        hx_post="/validate/email",
                        hx_trigger="keyup changed delay:500ms",
                        hx_target="#email-feedback")),
            Div(id="email-feedback", cls="feedback"),
            cls="form-group"
        ),
        
        # Password field with HTMX validation
        Div(
            Label("Password", 
                  Input(name="password", type="password", placeholder="Password", required=True,
                        hx_post="/validate/password",
                        hx_trigger="keyup changed delay:500ms",
                        hx_target="#password-feedback")),
            Div(id="password-feedback", cls="feedback"),
            cls="form-group"
        ),
        
        # Confirm password field with HTMX validation
        Div(
            Label("Confirm Password", 
                  Input(name="confirm_password", type="password", placeholder="Confirm Password", required=True,
                        hx_post="/validate/passwords-match",
                        hx_trigger="keyup changed delay:500ms",
                        hx_target="#confirm-feedback")),
            Div(id="confirm-feedback", cls="feedback"),
            cls="form-group"
        ),
        
        # Additional fields from ExtendedUser
        H2("Profile Information"),
        
        # First Name
        Div(
            Label("First Name", 
                  Input(name="first_name", placeholder="First Name")),
            cls="form-group"
        ),
        
        # Last Name
        Div(
            Label("Last Name", 
                  Input(name="last_name", placeholder="Last Name")),
            cls="form-group"
        ),
        
        # Phone
        Div(
            Label("Phone", 
                  Input(name="phone", placeholder="Phone Number")),
            cls="form-group"
        ),
        
        # Bio
        Div(
            Label("Bio", 
                  Textarea(name="bio", placeholder="Tell us about yourself", rows=3)),
            cls="form-group"
        ),
        
        # Profile Image URL
        Div(
            Label("Profile Image URL", 
                  Input(name="profile_image", placeholder="URL to your profile image")),
            cls="form-group"
        ),
        
        Button("Register", type="submit", id="register-button", disabled=True),
        P(A("Already have an account? Login", href="/login")),
        
        # Add some CSS for the form
        Style("""
            .form-group { margin-bottom: 1rem; }
            .feedback { min-height: 1.5rem; font-size: 0.875rem; margin-top: 0.25rem; }
            .feedback.valid { color: green; }
            .feedback.invalid { color: red; }
        """),
        
        action="/advanced-register",
        method="post",
        hx_post="/advanced-register",
        hx_target="#registration-result"
    )
    
    return Container(
        form,
        Div(id="registration-result")
    )

@app.post("/validate/username")
def validate_username_endpoint(username: str):
    is_valid, message = validation_manager.validate("username", username)
    cls = "valid" if is_valid else "invalid"
    return Div(message, cls=f"feedback {cls}")

@app.post("/validate/email")
def validate_email_endpoint(email: str):
    is_valid, message = validation_manager.validate("email_format", email)
    cls = "valid" if is_valid else "invalid"
    return Div(message, cls=f"feedback {cls}")

@app.post("/validate/password")
def validate_password_endpoint(password: str):
    score, issues = validation_manager.validate("password_strength", password)
    is_valid = score >= 50
    
    if is_valid:
        message = f"Password strength: {score}/100"
        cls = "valid"
    else:
        message = f"Issues: {', '.join(issues)}"
        cls = "invalid"
    
    return Div(message, cls=f"feedback {cls}")

@app.post("/validate/passwords-match")
def validate_passwords_match_endpoint(password: str, confirm_password: str):
    is_valid, message = validation_manager.validate("passwords_match", password, confirm_password)
    cls = "valid" if is_valid else "invalid"
    
    # Enable or disable the register button based on validation
    script = ""
    if is_valid:
        script = """
        <script>
            // Check if all validations are successful
            const feedbacks = document.querySelectorAll('.feedback');
            let allValid = true;
            
            feedbacks.forEach(feedback => {
                if (!feedback.classList.contains('valid')) {
                    allValid = false;
                }
            });
            
            // Enable or disable the register button
            document.getElementById('register-button').disabled = !allValid;
        </script>
        """
    
    return Div(
        Div(message, cls=f"feedback {cls}"),
        NotStr(script)
    )

@app.post("/advanced-register")
def post_advanced_register(username: str, email: str, password: str, confirm_password: str, 
                          first_name: str = "", last_name: str = "", phone: str = "", 
                          bio: str = "", profile_image: str = ""):
    try:
        # Validate username
        is_valid_username, username_message = validation_manager.validate("username", username)
        if not is_valid_username:
            return Div(
                H2("Registration Failed"),
                P(username_message),
                cls="error"
            )
        
        # Validate email
        is_valid_email, email_message = validation_manager.validate("email_format", email)
        if not is_valid_email:
            return Div(
                H2("Registration Failed"),
                P(email_message),
                cls="error"
            )
        
        # Validate password strength
        score, issues = validation_manager.validate("password_strength", password)
        if score < 50:
            return Div(
                H2("Registration Failed"),
                P(f"Password is not strong enough: {', '.join(issues)}"),
                cls="error"
            )
        
        # Validate passwords match
        is_match, match_message = validation_manager.validate("passwords_match", password, confirm_password)
        if not is_match:
            return Div(
                H2("Registration Failed"),
                P(match_message),
                cls="error"
            )
        
        # Create user with additional fields
        user = user_manager.create_user(
            email, 
            password,
            first_name=first_name,
            last_name=last_name,
            phone=phone,
            bio=bio,
            profile_image=profile_image
        )
        
        # Generate confirmation token
        token = user_manager.generate_confirmation_token(email, ConfirmTokenPeewee)
        
        # Send confirmation email
        send_confirmation_email(email, token)
        
        return Div(
            H2("Registration Successful"),
            P("A confirmation email has been sent to your email address."),
            P("Please check your email and click the confirmation link to activate your account."),
            P("For this example, the confirmation link is printed to the console."),
            A("Login", href="/login", cls="button"),
            cls="success"
        )
    except ValueError as e:
        return Div(
            H2("Registration Failed"),
            P(str(e)),
            cls="error"
        )

@app.get("/confirm-email/{token}")
def confirm_email(token: str):
    try:
        # Find token in database
        confirm_token = ConfirmTokenPeewee.get(token=token)
        
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
        confirm_token.save()
        
        return Container(
            H1("Email Confirmed"),
            P("Your email has been confirmed. You can now login."),
            A("Login", href="/login", cls="button")
        )
    except (KeyError, IndexError, NotFoundError, pw.DoesNotExist) as e:
        return Container(
            H1("Confirmation Failed"),
            P("Invalid confirmation link."),
            A("Register Again", href="/register", cls="button")
        )

@app.get("/login")
def get_login(session):
    user = get_current_user(session, user_manager)
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
def post_login(email: str, password: str, session):
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
    
    # Store user ID in session
    user_id = user.id if user_manager.is_db else user["id"]
    session['user_id'] = user_id
    
    # Redirect to dashboard
    # Use status_code 303 to change the method from POST to GET
    return RedirectResponse("/dashboard", status_code=303)

@app.get("/logout")
def logout(session):
    # Clear session
    if 'user_id' in session:
        del session['user_id']
    
    return RedirectResponse("/")

@app.get("/dashboard")
def dashboard(session):
    user = get_current_user(session, user_manager)
    # The auth_before Beforeware will handle redirecting if not logged in
    
    # Get user information
    if user_manager.is_db:
        email = user.email
        is_admin = user.is_admin
        first_name = user.first_name
        last_name = user.last_name
        phone = user.phone
        bio = user.bio
        profile_image = user.profile_image
    else:
        email = user["email"]
        is_admin = user["is_admin"]
        first_name = user.get("first_name", "")
        last_name = user.get("last_name", "")
        phone = user.get("phone", "")
        bio = user.get("bio", "")
        profile_image = user.get("profile_image", "")
    
    # Create user profile section
    profile_section = Div(
        H2("Your Profile"),
        Div(
            Div(
                Img(src=profile_image if profile_image else "https://via.placeholder.com/150", 
                    alt="Profile Image", width="150", height="150", style="border-radius: 50%;"),
                style="margin-right: 2rem;"
            ),
            Div(
                H3(f"{first_name} {last_name}" if first_name or last_name else email),
                P(f"Email: {email}"),
                P(f"Phone: {phone}") if phone else None,
                H4("Bio:"),
                P(bio) if bio else P("No bio provided."),
                style="flex: 1;"
            ),
            style="display: flex; margin-bottom: 2rem;"
        ),
        A("Edit Profile", href="/edit-profile", cls="button"),
        style="margin-bottom: 2rem;"
    )
    
    return Container(
        H1("Dashboard"),
        P(f"Welcome to your dashboard, {first_name or email}!"),
        P("This is a protected page that only logged-in users can access."),
        profile_section,
        Div(
            A("Logout", href="/logout", cls="button secondary"),
            A("Admin Panel", href="/admin", cls="button secondary") if is_admin else None,
            style="margin-top: 2rem;"
        )
    )

@app.get("/admin")
def admin_panel(session):
    user = get_current_user(session, user_manager)
    # The auth_before Beforeware will handle redirecting if not logged in
    
    is_admin = user.is_admin if user_manager.is_db else user["is_admin"]
    if not is_admin:
        return Container(
            H1("Access Denied"),
            P("You do not have permission to access this page."),
            A("Go to Dashboard", href="/dashboard", cls="button")
        )
    
    # Get maintenance mode status
    maintenance_mode = admin_manager.is_maintenance_mode()
    
    return Container(
        H1("Admin Panel"),
        P("Welcome to the admin panel!"),
        P("This is a protected page that only admin users can access."),
        
        H2("System Management"),
        Div(
            Form(
                Input(type="hidden", name="enabled", value=str(not maintenance_mode).lower()),
                Button(
                    "Disable Maintenance Mode" if maintenance_mode else "Enable Maintenance Mode", 
                    type="submit",
                    cls="button " + ("primary" if not maintenance_mode else "secondary")
                ),
                action="/admin/maintenance-mode",
                method="post"
            ),
            P(f"Maintenance Mode is currently {'enabled' if maintenance_mode else 'disabled'}."),
            style="margin-bottom: 2rem;"
        ),
        
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

@app.post("/admin/maintenance-mode")
def toggle_maintenance_mode(enabled: str, session):
    user = get_current_user(session, user_manager)
    # The auth_before Beforeware will handle redirecting if not logged in
    
    is_admin = user.is_admin if user_manager.is_db else user["is_admin"]
    if not is_admin:
        return Container(
            H1("Access Denied"),
            P("You do not have permission to access this page."),
            A("Go to Dashboard", href="/dashboard", cls="button")
        )
    
    # Convert string to boolean
    enable_mode = enabled.lower() == "true"
    
    # Set maintenance mode
    admin_manager.set_maintenance_mode(enable_mode)
    
    return RedirectResponse("/admin", status_code=303)

@app.get("/maintenance")
def maintenance_page():
    """
    Maintenance page shown to non-admin users when maintenance mode is enabled.
    """
    return Container(
        H1("System Maintenance"),
        P("The system is currently undergoing maintenance."),
        P("Please check back later."),
        P("If you are an administrator, please log in to access the system."),
        A("Login", href="/login", cls="button"),
        style="text-align: center; max-width: 600px; margin: 0 auto; padding: 2rem;"
    )

@app.get("/admin/backup-db")
def backup_db(session):
    user = get_current_user(session, user_manager)
    # The auth_before Beforeware will handle redirecting if not logged in
    
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
def download_db(session):
    user = get_current_user(session, user_manager)
    # The auth_before Beforeware will handle redirecting if not logged in
    
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
def get_upload_db(session):
    user = get_current_user(session, user_manager)
    # The auth_before Beforeware will handle redirecting if not logged in
    
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
        Input(name="dbfile", type="file", accept=".db", required=True),
        Button("Upload", type="submit"),
        A("Cancel", href="/admin", cls="button secondary"),
        action="/admin/upload-db",
        method="post",
        enctype="multipart/form-data"
    )
    
    return Container(form)

@app.post("/admin/upload-db")
async def post_upload_db(request, session):
    user = get_current_user(session, user_manager)
    # The auth_before Beforeware will handle redirecting if not logged in
    
    is_admin = user.is_admin if user_manager.is_db else user["is_admin"]
    if not is_admin:
        return Container(
            H1("Access Denied"),
            P("You do not have permission to access this page."),
            A("Go to Dashboard", href="/dashboard", cls="button")
        )
    
    try:
        # Process form data
        form = await request.form()
        file = form["dbfile"]
        if not file.filename.endswith('.db'):
            return Titled("Error", P("Invalid file type. Please upload a .db file."))
        
        # Use AdminManager to upload database
        file_content = await file.read()
        admin_manager.upload_database(os.path.join(db_path, "example.db"), file_content)
        
        return RedirectResponse("/admin?success=true", status_code=303)
            
    except ValueError as e:
        return Titled("Error", P(str(e)))
    except Exception as e:
        return Titled("Error", P(f"Failed to process upload request: {str(e)}"))

@app.get("/edit-profile")
def get_edit_profile(session):
    user = get_current_user(session, user_manager)
    # The auth_before Beforeware will handle redirecting if not logged in
    
    # Get user information
    if user_manager.is_db:
        email = user.email
        first_name = user.first_name
        last_name = user.last_name
        phone = user.phone
        bio = user.bio
        profile_image = user.profile_image
    else:
        email = user["email"]
        first_name = user.get("first_name", "")
        last_name = user.get("last_name", "")
        phone = user.get("phone", "")
        bio = user.get("bio", "")
        profile_image = user.get("profile_image", "")
    
    form = Form(
        H1("Edit Profile"),
        P(f"Email: {email}"),
        
        # First Name
        Div(
            Label("First Name", 
                  Input(name="first_name", placeholder="First Name", value=first_name)),
            cls="form-group"
        ),
        
        # Last Name
        Div(
            Label("Last Name", 
                  Input(name="last_name", placeholder="Last Name", value=last_name)),
            cls="form-group"
        ),
        
        # Phone
        Div(
            Label("Phone", 
                  Input(name="phone", placeholder="Phone Number", value=phone)),
            cls="form-group"
        ),
        
        # Bio
        Div(
            Label("Bio", 
                  Textarea(name="bio", placeholder="Tell us about yourself", rows=3, value=bio)),
            cls="form-group"
        ),
        
        # Profile Image URL
        Div(
            Label("Profile Image URL", 
                  Input(name="profile_image", placeholder="URL to your profile image", value=profile_image)),
            cls="form-group"
        ),
        
        Button("Update Profile", type="submit"),
        A("Cancel", href="/dashboard", cls="button secondary"),
        action="/edit-profile",
        method="post"
    )
    
    return Container(form)

@app.post("/edit-profile")
def post_edit_profile(first_name: str = "", last_name: str = "", phone: str = "", 
                     bio: str = "", profile_image: str = "", session=None):
    user = get_current_user(session, user_manager)
    # The auth_before Beforeware will handle redirecting if not logged in
    
    try:
        # Update user profile
        if user_manager.is_db:
            # Update FastHTML database object
            user.first_name = first_name
            user.last_name = last_name
            user.phone = phone
            user.bio = bio
            user.profile_image = profile_image
            user_manager.users.update(user)
        else:
            # Update dictionary store
            user["first_name"] = first_name
            user["last_name"] = last_name
            user["phone"] = phone
            user["bio"] = bio
            user["profile_image"] = profile_image
        
        return RedirectResponse("/dashboard", status_code=303)
    except Exception as e:
        return Container(
            H1("Profile Update Failed"),
            P(f"Error: {str(e)}"),
            A("Try Again", href="/edit-profile", cls="button")
        )


if __name__ == "__main__":
    print("\nStarting example server...")
    print("Admin user created with email:", admin_email)
    print("Admin user password:", admin_password)
    serve(host="localhost", port=8000)

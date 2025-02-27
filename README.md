A Python library for user authentication, admin management, and database administration in FastHTML applications.

## Features

- User management (registration, authentication, and confirmation)
- Admin user creation and management
- Sqlite database download, upload, backup and restore
- Built-in validation functions for passwords, emails, and more
- Extensible validation system for custom validation rules
- HTMX integration for real-time form validation
- OAuth integration 

## Installation

You can install the package using pip or uv.

```bash
pip install fasthtml-admin
```

## Usage

For detailed usage, look at our [example application](https://github.com/AndreasThinks/fasthtml-admin/blob/main/example.py).

### User Management

```python
from fasthtml.common import database
from fasthtml_admin import UserManager, UserCredential

# Create a FastHTML database
db = database("data/myapp.db")

# Initialize UserManager with the database
user_manager = UserManager(db)

# Create a new user
try:
    user = user_manager.create_user(
        email="user@example.com",
        password="secure_password"
    )
    print(f"User created with ID: {user.id}")
except ValueError as e:
    print(f"Error creating user: {e}")

# Authenticate a user
user = user_manager.authenticate_user("user@example.com", "secure_password")
if user:
    print(f"User authenticated: {user.email}")
else:
    print("Authentication failed")

# Confirm a user
success = user_manager.confirm_user("user@example.com")
if success:
    print("User confirmed")
else:
    print("User confirmation failed")
```

### Admin Management

You can quickly create admin users, who have elevated access.

```python
from fasthtml.common import database
from fasthtml_admin import UserManager, AdminManager

# Create a FastHTML database
db = database("data/myapp.db")

# Initialize UserManager with the database
user_manager = UserManager(db)

# Initialize AdminManager with the UserManager
admin_manager = AdminManager(user_manager)

# Ensure an admin user exists
admin = admin_manager.ensure_admin("admin@example.com", "admin_password")
print(f"Admin user: {admin.email}")

# Backup the database
backup_path = admin_manager.backup_database("data/myapp.db", backup_dir="backups")
print(f"Database backed up to: {backup_path}")

# Restore the database from a backup
admin_manager.restore_database("data/myapp.db", backup_path)
print("Database restored successfully")

# Upload a database file
with open("path/to/uploaded_file.db", "rb") as f:
    file_content = f.read()
    admin_manager.upload_database("data/myapp.db", file_content)
print("Database uploaded successfully")
```

### User Confirmation

If you wish to confirm users (for example, using an email confirmation flow), you can create and register confirmation tokens.

```python
from fasthtml.common import database
from fasthtml_admin import UserManager, ConfirmToken

# Create a FastHTML database
db = database("data/myapp.db")

# Create a token store for confirmation tokens
confirm_tokens = db.create(ConfirmToken, pk="token")

# Initialize UserManager with the database
user_manager = UserManager(db)

# Generate a confirmation token
token = user_manager.generate_confirmation_token("user@example.com", confirm_tokens)
print(f"Generated token: {token}")

# Define an email sender function
def send_confirmation_email(email, token):
    print(f"Sending confirmation email to {email}")
    print(f"Confirmation link: http://example.com/confirm-email/{token}")
    return True

# Send a confirmation email
send_confirmation_email("user@example.com", token)

# In your route handler for confirmation:
# confirm_token = confirm_tokens[token]
# user_manager.confirm_user(confirm_token.email)
# confirm_token.is_used = True
# confirm_tokens.update(confirm_token)
```

### Authentication with Beforeware

The library provides functions to implement FastHTML's best practices for authentication using Beforeware:

```python
from fasthtml.common import *
from fasthtml_admin import UserManager, auth_before, get_current_user

# Initialize UserManager
db = database("data/myapp.db")
user_manager = UserManager(db)

# Define a custom auth_before function that uses the library's auth_before
def app_auth_before(req, sess):
    return auth_before(req, sess, user_manager, 
                      login_url='/login',
                      public_paths=['/', '/login', '/register', '/confirm-email'])

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

# In your route handlers, use get_current_user to get the current user
@app.get("/dashboard")
def dashboard(session):
    user = get_current_user(session, user_manager)
    # The auth_before Beforeware will handle redirecting if not logged in
    
    return Container(
        H1("Dashboard"),
        P(f"Welcome to your dashboard, {user.email}!"),
        # ...
    )
```

## Integrating with Existing FastHTML Applications

### Step 1: Install the Library

```bash
pip install fasthtml-admin
```

### Step 2: Set Up Database and User Management

```python
from fasthtml.common import *
from fasthtml_admin import UserManager, UserCredential, AdminManager, ConfirmToken

# Create or connect to your existing database
db = database("data/myapp.db")

# Create a token store for confirmation tokens
confirm_tokens = db.create(ConfirmToken, pk="token")

# Initialize UserManager with your database
user_manager = UserManager(db)

# Initialize AdminManager with your UserManager
admin_manager = AdminManager(user_manager)

# Create an admin user if needed
admin_email = "admin@example.com"
admin_password = "adminpass"
admin_manager.ensure_admin(admin_email, admin_password)
```

### Extending the User Class

You can extend the basic `UserCredential` class with your own fields:

```python
from dataclasses import dataclass
from fasthtml_admin import UserCredential, UserManager

@dataclass
class ExtendedUser(UserCredential):
    """
    Extended user class with additional fields.
    """
    first_name: str = ""
    last_name: str = ""
    phone: str = ""
    bio: str = ""
    profile_image: str = ""

# Initialize UserManager with the extended user class
user_manager = UserManager(db, user_class=ExtendedUser)

# Create a user with additional fields
user = user_manager.create_user(
    email="user@example.com",
    password="secure_password",
    first_name="John",
    last_name="Doe",
    phone="555-123-4567",
    bio="A short bio about the user",
    profile_image="https://example.com/profile.jpg"
)
```

This allows you to store additional user information in the database without having to create and manage separate tables.

### Step 3: Set Up Authentication with Beforeware

```python
from fasthtml.common import *
from fasthtml_admin import auth_before, get_current_user

# Define a custom auth_before function that uses the library's auth_before
def app_auth_before(req, sess):
    return auth_before(req, sess, user_manager, 
                      login_url='/login',
                      public_paths=['/', '/login', '/register', '/confirm-email'])

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
```

### Step 4: Add Authentication Routes

```python
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
```

### Step 5: Add Registration and Confirmation Routes

```python
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
```

### Step 6: Protect Your Routes

With the auth_before Beforeware in place, your routes are automatically protected. You can still check for admin privileges or other specific conditions in your route handlers:

```python
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
    
    # Your admin panel code here
    return Container(
        H1("Admin Panel"),
        # ...
    )
```

### Best Practices

1. **Security**: Always store passwords securely using the provided `hash_password` function.
2. **Sessions**: Use FastHTML's built-in session support with a secure random key.
3. **Authentication**: Use the provided `auth_before` function with Beforeware for centralized authentication.
4. **User Management**: Use the `get_current_user` function to retrieve the current user from the session.
5. **Email Confirmation**: Implement a real email sending function for production.
6. **Error Handling**: Add comprehensive error handling for database operations.
7. **CSRF Protection**: Add CSRF protection for form submissions.
8. **Rate Limiting**: Implement rate limiting for login attempts to prevent brute force attacks.
9. **HTTPS**: In production, set `sess_https_only=True` and use HTTPS.

## Validation System

The library includes a robust validation system for validating user input. It provides built-in validators for common validation tasks and allows you to register custom validators.

### Built-in Validators

The following validators are included out of the box:

1. **Password Strength Validation**
   ```python
   from fasthtml_admin import validation_manager
   
   # Returns a score (0-100) and a list of issues
   score, issues = validation_manager.validate("password_strength", "my_password")
   
   # Check if password is strong enough
   if score >= 50:
       print("Password is strong enough")
   else:
       print(f"Password issues: {', '.join(issues)}")
   ```

2. **Email Format Validation**
   ```python
   from fasthtml_admin import validation_manager
   
   # Returns a boolean and a message
   is_valid, message = validation_manager.validate("email_format", "user@example.com")
   
   if is_valid:
       print("Email format is valid")
   else:
       print(message)
   ```

3. **Passwords Match Validation**
   ```python
   from fasthtml_admin import validation_manager
   
   # Returns a boolean and a message
   is_match, message = validation_manager.validate("passwords_match", "password1", "password1")
   
   if is_match:
       print("Passwords match")
   else:
       print(message)
   ```

### Custom Validators

You can register your own custom validators with the validation system:

```python
from fasthtml_admin import validation_manager

# Define a custom validator function
def validate_username(username: str) -> tuple[bool, str]:
    """
    Validate username format and return (is_valid, message).
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

# Use the custom validator
is_valid, message = validation_manager.validate("username", "user123")
```

### HTMX Integration for Real-time Validation

The library can be easily integrated with HTMX to provide real-time validation feedback to users. Here's an example of how to set up real-time validation for a registration form:

```python
@app.get("/register")
def get_register(session):
    # Create a form with HTMX validation
    form = Form(
        H1("Registration with Real-time Validation"),
        
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
        
        Button("Register", type="submit"),
        action="/register",
        method="post"
    )
    
    return Container(form)

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
```

This setup provides immediate feedback to users as they type, improving the user experience and reducing form submission errors.

## Example Applications

The library includes example FastHTML applications that demonstrate all the features:

### Basic Example

```bash
cd fasthtml-admin
python example.py
```

This will start a web server at http://localhost:8000 with the following features:
- User registration with email confirmation
- User login with session management
- Admin panel with database backup and restore
- Authentication using FastHTML's Beforeware
- Real-time form validation using HTMX

### OAuth Example

```bash
cd fasthtml-admin
python example_oauth.py
```

This example demonstrates OAuth integration with the fasthtml_admin library:
- Authentication with GitHub OAuth
- Integration with the UserManager for user creation and retrieval
- Protected routes with authentication
- Session management

To use the OAuth example, you need to:
1. Register an OAuth app on GitHub (or your preferred provider)
2. Set the required environment variables (e.g., GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET)
3. Set the Authorization callback URL to http://localhost:8000/auth_redirect

## OAuth Integration

The library includes an `OAuthManager` class that integrates with FastHTML's OAuth support to provide third-party authentication. Here's how to use it:

```python
from fasthtml.common import *
from fasthtml.oauth import GitHubAppClient
from fasthtml_admin import UserManager, OAuthManager, get_current_user

# Initialize UserManager
db = database("data/myapp.db")
user_manager = UserManager(db)

# Create an OAuth client
client = GitHubAppClient(
    client_id=os.environ.get("GITHUB_CLIENT_ID"),
    client_secret=os.environ.get("GITHUB_CLIENT_SECRET")
)

# Create a FastHTML app
app, rt = fast_app(
    secret_key="your-secret-key-here",
    session_cookie="session",
    max_age=3600 * 24 * 7  # 7 days
)

# Initialize OAuthManager with the app, client, and user manager
oauth = OAuthManager(
    app=app,
    client=client,
    user_manager=user_manager,
    redir_path='/auth_redirect',  # Path for OAuth callback
    login_path='/login',          # Path to redirect to for login
    dashboard_path='/dashboard'   # Path to redirect to after successful authentication
)

# Add routes
@app.get('/')
def home(session, request):
    user = get_current_user(session, user_manager)
    login_link = oauth.login_link(request)
    
    if user:
        # User is logged in
        return Container(
            H1(f"Welcome, {user.email}!"),
            P("You are logged in via OAuth."),
            A("Logout", href="/logout", cls="button")
        )
    else:
        # User is not logged in
        return Container(
            H1("Welcome"),
            P("Please log in to continue."),
            A("Login with GitHub", href=login_link, cls="button")
        )

@app.get('/dashboard')
def dashboard(session):
    user = get_current_user(session, user_manager)
    # Display user information
    return Container(
        H1(f"Welcome, {user.email}!"),
        P("You are logged in via OAuth.")
    )
```

The `OAuthManager` class handles:

1. Setting up the OAuth flow with the provider
2. Creating or retrieving users based on OAuth information
3. Managing user sessions
4. Protecting routes with authentication

It works with any OAuth provider supported by FastHTML, including:
- GitHub
- Google
- Discord
- HuggingFace
- Auth0

For a complete example, see `example_oauth.py`.

## Maintenance Mode

The library includes a persistent maintenance mode feature that allows administrators to temporarily restrict access to the system for all non-admin users. When maintenance mode is enabled, non-admin users (including anonymous users) are redirected to a maintenance page.

```python
from fasthtml.common import *
from fasthtml_admin import UserManager, AdminManager, auth_before

# Initialize UserManager and AdminManager
db = database("data/myapp.db")
user_manager = UserManager(db)
admin_manager = AdminManager(user_manager)

# Set up authentication with maintenance mode support
def app_auth_before(req, sess):
    return auth_before(req, sess, user_manager, 
                      login_url='/login',
                      public_paths=['/', '/register'],
                      admin_manager=admin_manager,
                      maintenance_url='/maintenance')

# Create a FastHTML app with authentication
beforeware = Beforeware(app_auth_before)
app, rt = fast_app(
    secret_key="your-secret-key-here",
    before=beforeware,
    session_cookie="session"
)

# Add a maintenance page
@app.get("/maintenance")
def maintenance_page():
    return Container(
        H1("System Maintenance"),
        P("The system is currently undergoing maintenance."),
        P("Please check back later."),
        P("If you are an administrator, please log in to access the system."),
        A("Login", href="/login", cls="button")
    )

# Add controls for admins to toggle maintenance mode
@app.post("/admin/maintenance-mode")
def toggle_maintenance_mode(enabled: str, session):
    user = get_current_user(session, user_manager)
    is_admin = user.is_admin if user_manager.is_db else user["is_admin"]
    
    if not is_admin:
        return RedirectResponse("/dashboard", status_code=303)
    
    # Convert string to boolean
    enable_mode = enabled.lower() == "true"
    
    # Set maintenance mode
    admin_manager.set_maintenance_mode(enable_mode)
    
    return RedirectResponse("/admin", status_code=303)
```

This example demonstrates:
1. Setting up the AdminManager with maintenance mode support
2. Configuring the auth_before function to check for maintenance mode
3. Adding a maintenance page that users will be redirected to
4. Adding controls for admins to toggle maintenance mode on/off

When maintenance mode is enabled:
- Admin users can still access all parts of the system
- Non-admin users (including anonymous users) are redirected to the maintenance page when they try to access any part of the system
- The login page remains accessible so admins can log in
- The maintenance page is always accessible

### Persistent Maintenance Mode

The maintenance mode state is stored in the database, making it persistent across application restarts. This means that if you enable maintenance mode and restart your application, it will remain in maintenance mode.

```python
# Initialize AdminManager
admin_manager = AdminManager(user_manager)

# Check current maintenance mode status
is_maintenance = admin_manager.is_maintenance_mode()
print(f"Maintenance mode is {'enabled' if is_maintenance else 'disabled'}")

# Enable maintenance mode
admin_manager.set_maintenance_mode(True)

# Disable maintenance mode
admin_manager.set_maintenance_mode(False)
```

The maintenance mode state is stored in a system_settings table in the database, which is automatically created when you initialize the AdminManager. This ensures that the maintenance mode state is preserved even if the application is restarted.

## Database Upload Example

Here's an example of how to implement a database upload feature in your FastHTML application:

```python
from fasthtml.common import limiter, RedirectResponse, Container, H1, P, A, Form, Input, Button, Titled

@app.get("/admin/upload-db")
def get_upload_db(session):
    user = get_current_user(session, user_manager)
    # Check if user is admin
    is_admin = user.is_admin if user_manager.is_db else user["is_admin"]
    if not is_admin:
        return Container(
            H1("Access Denied"),
            P("You do not have permission to access this page."),
            A("Go to Dashboard", href="/dashboard", cls="button")
        )
    
    # Create upload form
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

@limiter.limit("30/day")  # Rate limit to prevent abuse
@app.post("/admin/upload-db")
async def post_upload_db(request, session):
    user = get_current_user(session, user_manager)
    # Check if user is admin
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
        admin_manager.upload_database("data/myapp.db", file_content)
        
        return RedirectResponse("/admin?success=true", status_code=303)
            
    except ValueError as e:
        return Titled("Error", P(str(e)))
    except Exception as e:
        return Titled("Error", P(f"Failed to process upload request: {str(e)}"))
```

This example demonstrates:
1. A GET route to display the upload form
2. A POST route to handle the file upload
3. Rate limiting to prevent abuse
4. Admin permission checks
5. File validation (must be a .db file)
6. Using the AdminManager's upload_database method to handle the upload
7. Error handling for different types of errors

## Customization

The library is designed to be flexible and customizable. You can extend the provided classes or implement your own versions of the interfaces to fit your specific needs.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

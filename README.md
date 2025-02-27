# FastHTML Admin Library

A Python library for user authentication, admin management, and database administration in FastHTML applications.

## Features

- User management (registration, authentication, and confirmation)
- Admin user creation and management
- Database backup and restore
- Works with both FastHTML database and dictionary stores

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/fasthtml-admin.git

# Install the package
cd fasthtml-admin
pip install -e .
```

## Usage

### User Management with FastHTML Database

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

### User Management with Dictionary Store

```python
from fasthtml_admin import UserManager

# Create a dictionary store
users_store = {}

# Initialize UserManager with the dictionary store
user_manager = UserManager(users_store)

# Create a new user
user = user_manager.create_user("user@example.com", "secure_password")
print(f"User created with ID: {user['id']}")

# Authenticate a user
user = user_manager.authenticate_user("user@example.com", "secure_password")
if user:
    print(f"User authenticated: {user['email']}")
else:
    print("Authentication failed")
```

### Admin Management

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
```

### Email Confirmation

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

### Step 3: Add Authentication Routes

```python
# Simple session management
sessions = {}

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

# Login route
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
```

### Step 4: Add Registration and Confirmation Routes

```python
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

### Step 5: Add Admin Panel Routes

```python
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
        backup_path = admin_manager.backup_database("data/myapp.db")
        
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
        db_file_path = "data/myapp.db"
        
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
```

### Step 6: Protect Your Routes

Add authentication checks to your existing routes to ensure only logged-in users can access protected pages:

```python
@app.get("/dashboard")
def dashboard(req):
    user = get_current_user(req)
    if not user:
        return RedirectResponse("/login")
    
    # Your existing dashboard code here
    return Container(
        H1("Dashboard"),
        P(f"Welcome to your dashboard, {user.email}!"),
        # ...
    )
```

### Best Practices

1. **Security**: Always store passwords securely using the provided `hash_password` function.
2. **Sessions**: Consider using a more persistent session store for production applications.
3. **Email Confirmation**: Implement a real email sending function for production.
4. **Error Handling**: Add comprehensive error handling for database operations.
5. **CSRF Protection**: Add CSRF protection for form submissions.
6. **Rate Limiting**: Implement rate limiting for login attempts to prevent brute force attacks.

## Example Application

The library includes an example FastHTML application that demonstrates all the features. To run the example:

```bash
cd fasthtml-admin
python example.py
```

This will start a web server at http://localhost:8000 with the following features:
- User registration with email confirmation
- User login
- Admin panel with database backup and restore

## Customization

The library is designed to be flexible and customizable. You can extend the provided classes or implement your own versions of the interfaces to fit your specific needs.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

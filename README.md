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
from fasthtml_admin import UserManager
from dataclasses import dataclass
from datetime import datetime

# Create a FastHTML database
db = database("data/myapp.db")

# Create a token store for confirmation tokens
@dataclass
class ConfirmToken:
    token: str
    email: str
    expiry: datetime
    is_used: bool = False

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

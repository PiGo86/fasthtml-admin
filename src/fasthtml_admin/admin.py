"""
Admin management module for the fasthtml_admin library.
"""

import secrets
from datetime import datetime
import os
import sqlite3

from .utils import hash_password

class AdminManager:
    """
    Manages admin users and admin-related operations.
    """
    def __init__(self, user_manager):
        """
        Initialize the AdminManager with a UserManager instance.
        
        Args:
            user_manager: An instance of UserManager to handle user operations
        """
        self.user_manager = user_manager
    
    def ensure_admin(self, admin_email, admin_password):
        """
        Ensure that an admin user exists with the given email and password.
        If the user doesn't exist, it will be created.
        If the user exists but is not an admin, it will be promoted to admin.
        
        Args:
            admin_email: Admin user's email address
            admin_password: Admin user's password (plain text)
            
        Returns:
            The admin user object
        """
        try:
            # Check if user exists
            if self.user_manager.is_db:
                user = self.user_manager.users[admin_email]
                
                # If user exists but is not admin, promote to admin
                if not user.is_admin:
                    user.is_admin = True
                    user.is_confirmed = True  # Admins are auto-confirmed
                    self.user_manager.users.update(user)
                
                return user
            else:
                user = self.user_manager.users.get(admin_email)
                
                if user:
                    # If user exists but is not admin, promote to admin
                    if not user.get("is_admin", False):
                        user["is_admin"] = True
                        user["is_confirmed"] = True  # Admins are auto-confirmed
                    
                    return user
        except (KeyError, IndexError, Exception) as e:
            # User doesn't exist, create a new admin user
            # NotFoundError is raised by FastHTML database when a record is not found
            if not isinstance(e, Exception) or "NotFoundError" not in str(type(e)):
                raise  # Re-raise if it's not a NotFoundError
            pass
        
        # Create new admin user
        user_data = {
            "id": secrets.token_hex(16),
            "email": admin_email,
            "pwd": hash_password(admin_password),
            "created_at": datetime.now(),
            "is_confirmed": True,  # Admins are auto-confirmed
            "is_admin": True
        }
        
        if self.user_manager.is_db:
            # Insert into FastHTML database
            user = self.user_manager.users.insert(user_data)
        else:
            # Insert into dictionary store
            self.user_manager.users[admin_email] = user_data
            user = user_data
            
        return user

    def backup_database(self, db_path, backup_dir="backups"):
        """
        Create a backup of the database.
        
        Args:
            db_path: Path to the database file
            backup_dir: Directory to store backups
            
        Returns:
            Path to the backup file
        """
        if not os.path.exists(db_path):
            raise FileNotFoundError(f"Database file not found: {db_path}")
            
        # Create backup directory if it doesn't exist
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
            
        # Generate backup filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"{os.path.basename(db_path)}.{timestamp}.bak"
        backup_path = os.path.join(backup_dir, backup_filename)
        
        # Create backup using SQLite's backup API
        source = sqlite3.connect(db_path)
        dest = sqlite3.connect(backup_path)
        source.backup(dest)
        source.close()
        dest.close()
        
        return backup_path
        
    def restore_database(self, db_path, backup_path):
        """
        Restore a database from a backup.
        
        Args:
            db_path: Path to the target database file
            backup_path: Path to the backup file
            
        Returns:
            True if successful, False otherwise
        """
        if not os.path.exists(backup_path):
            raise FileNotFoundError(f"Backup file not found: {backup_path}")
            
        try:
            # Create a temporary backup of the current database
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            temp_backup = f"{db_path}.{timestamp}.temp"
            
            # Backup current database
            source = sqlite3.connect(db_path)
            temp = sqlite3.connect(temp_backup)
            source.backup(temp)
            source.close()
            temp.close()
            
            # Restore from backup
            backup = sqlite3.connect(backup_path)
            dest = sqlite3.connect(db_path)
            backup.backup(dest)
            backup.close()
            dest.close()
            
            # Remove temporary backup
            os.remove(temp_backup)
            
            return True
        except Exception as e:
            # If restoration fails, try to restore from temporary backup
            if os.path.exists(temp_backup):
                try:
                    temp = sqlite3.connect(temp_backup)
                    dest = sqlite3.connect(db_path)
                    temp.backup(dest)
                    temp.close()
                    dest.close()
                    os.remove(temp_backup)
                except:
                    pass
            
            raise e

"""
Admin management module for the fasthtml_admin library.
"""

import secrets
from datetime import datetime
import os
import sqlite3

from .utils import hash_password
from .auth import Storage
from .models import SystemSetting
from .models.peewee_adaptator import SystemSettingPeewee

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

        match self.user_manager.storage:

            case Storage.FAST_HTML:
                # Create settings table if using FastHTML database
                self.settings = self.user_manager.db.create(SystemSetting,
                                                            pk="key",
                                                            name="system_settings",
                                                            )
            
                # Initialize maintenance mode setting if it doesn't exist
                try:
                    self.settings["maintenance_mode"]
                except (KeyError, IndexError, Exception) as e:
                    # Setting doesn't exist, create it
                    if not isinstance(e, Exception) or "NotFoundError" not in str(type(e)):
                        raise  # Re-raise if it's not a NotFoundError

                    self.settings.insert({
                        "key": "maintenance_mode",
                        "value": "false",
                        "updated_at": datetime.now()
                    })

            case Storage.PEEWEE:
                # Create settings table if using peewee database
                self.settings = SystemSettingPeewee
                self.user_manager.db.create_tables([SystemSettingPeewee,])

                # Initialize maintenance mode setting if it doesn't exist
                maintenance_mode = self.settings.get_or_none(key='maintenance_mode')
                if maintenance_mode is None:
                    self.settings.create(key='maintenance_mode',
                                         value='false',
                                         updated_at=datetime.now(),
                                         )

            case _:
                # Using dictionary store
                # Initialize settings dictionary if it doesn't exist
                if not hasattr(self.user_manager, "settings"):
                    self.user_manager.settings = {}
            
                # Initialize maintenance mode setting if it doesn't exist
                if "maintenance_mode" not in self.user_manager.settings:
                    self.user_manager.settings["maintenance_mode"] = {
                        "key": "maintenance_mode",
                        "value": "false",
                        "updated_at": datetime.now()
                    }
    
    def set_maintenance_mode(self, enabled):
        """
        Enable or disable maintenance mode.
        
        Args:
            enabled: Boolean indicating whether maintenance mode should be enabled
            
        Returns:
            The current maintenance mode state
        """
        value = str(enabled).lower()

        match self.user_manager.storage:

            case Storage.FAST_HTML: # Update setting in FastHTML database
                setting = self.settings["maintenance_mode"]
                setting.value = value
                setting.updated_at = datetime.now()
                self.settings.update(setting)

            case Storage.PEEWEE: # Update setting in peewee database
                setting = self.settings.get(key='maintenance_mode')
                setting.value = value
                setting.updated_at = datetime.now()
                setting.save()

            case _: # Update setting in dictionary store
                self.user_manager.settings["maintenance_mode"]["value"] = value
                self.user_manager.settings["maintenance_mode"]["updated_at"] = datetime.now()
        
        return enabled
    
    def is_maintenance_mode(self):
        """
        Check if the system is in maintenance mode.
        
        Returns:
            Boolean indicating whether maintenance mode is enabled
        """
        try:
            match self.user_manager.storage:
                case Storage.FAST_HTML: # Get setting from FastHTML database
                    setting = self.settings["maintenance_mode"]
                    return setting.value.lower() == "true"
                case Storage.PEEWEE: # Get setting from peewee database
                    setting = self.settings.get_or_none(key='maintenance_mode')
                    if setting is not None:
                        return setting.value.lower() == "true"
                    else:
                        return False
                case _: # Get setting from dictionary store
                    return self.user_manager.settings["maintenance_mode"]["value"].lower() == "true"
        except (KeyError, IndexError, Exception) as e:
            # Setting doesn't exist, return default value
            return False
    
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
            match self.user_manager.storage:

                case Storage.FAST_HTML:
                    user = self.user_manager.users[admin_email]
                
                    # If user exists but is not admin, promote to admin
                    if not user.is_admin:
                        user.is_admin = True
                        user.is_confirmed = True  # Admins are auto-confirmed
                        self.user_manager.users.update(user)

                    return user

                case Storage.PEEWEE:
                    user = self.user_manager.users.get_or_none(email=admin_email)

                    # If user exists but is not admin, promote to admin
                    if user is not None:
                        if not user.is_admin:
                            user.is_admin = True
                            user.is_confirmed = True  # Admins are auto-confirmed
                            user.save()

                        return user

                case _:
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

        match self.user_manager.storage:
            case Storage.FAST_HTML: # Insert into FastHTML database
                user = self.user_manager.users.insert(user_data)
            case Storage.PEEWEE:
                user = self.user_manager.users.create(**user_data)
            case _: # Insert into dictionary store
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
            
    def upload_database(self, db_path, file_content):
        """
        Upload and replace the current database with the provided file content.
        
        Args:
            db_path: Path to the target database file
            file_content: Binary content of the uploaded database file
            
        Returns:
            True if successful
            
        Raises:
            ValueError: If the file is not a valid SQLite database
            Exception: If the upload fails
        """
        # Create a temporary file for the uploaded content
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        temp_path = f"{os.path.dirname(db_path)}/upload_temp_{timestamp}.db"
        backup_path = None
        
        try:
            # Save uploaded content to temporary file
            with open(temp_path, "wb") as f:
                f.write(file_content)
            
            # Verify it's a valid SQLite database
            try:
                temp_conn = sqlite3.connect(temp_path)
                temp_conn.cursor().execute("SELECT name FROM sqlite_master WHERE type='table'")
                temp_conn.close()
            except sqlite3.Error:
                os.remove(temp_path)
                raise ValueError("Invalid SQLite database file.")
            
            # Create backup of current database using SQLite backup API
            backup_path = f"{os.path.dirname(db_path)}/backup_{timestamp}.db"
            source = sqlite3.connect(db_path)
            backup = sqlite3.connect(backup_path)
            source.backup(backup)
            source.close()
            backup.close()
            
            try:
                # Replace current database with uploaded one using SQLite backup API
                dest = sqlite3.connect(db_path)
                source = sqlite3.connect(temp_path)
                source.backup(dest)
                source.close()
                dest.close()
                
                # Clean up temporary files
                os.remove(temp_path)
                os.remove(backup_path)
                
                return True
                
            except Exception as e:
                # Restore from backup if something went wrong
                if os.path.exists(backup_path):
                    self.restore_database(db_path, backup_path)
                    os.remove(backup_path)
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                raise Exception(f"Failed to upload database: {str(e)}")
                
        except Exception as e:
            # Clean up temporary files
            if os.path.exists(temp_path):
                os.remove(temp_path)
            if os.path.exists(backup_path):
                os.remove(backup_path)
            raise e

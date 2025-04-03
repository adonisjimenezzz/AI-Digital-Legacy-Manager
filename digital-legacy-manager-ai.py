"""
Digital Legacy Manager - AI-Powered Virtual Assistant

Description:
    This project provides a comprehensive framework for building an AI-powered virtual assistant
    designed to manage digital legacies. It includes components for user management,
    data storage, AI integration, task automation, and more.  This version adds more
    robustness, error handling, and features.

Modules:
    - user_management.py: Handles user authentication, profile management, and legacy planning.
    - data_storage.py: Manages data persistence using a database.
    - ai_integration.py: Integrates with AI models for NLP and task automation.
    - task_automation.py: Automates legacy-related tasks.
    - interaction.py: Manages user interactions (CLI and potential web).
    - utils.py: Provides utility functions.
    - legacy_planning.py: Handles legacy plan creation and management.
    - security.py: Implements security measures.
    - error_handling.py: Defines custom exceptions and error handling.
    - config.py: Manages application configuration.
    - models.py: Defines data models using Pydantic.

Documentation:
    - README.md: Project overview, setup, and usage.
    - docs/: Detailed module and API documentation.

Framework:
    - Modular design.
    - Object-oriented programming.
    - Integration with libraries.
    - Uses SQLite database.
    - Basic CLI interaction.

Example Usage:
    python interaction.py --mode cli
"""

import os
import json
import datetime
import logging
import uuid
import sqlite3
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, EmailStr, ValidationError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# Configuration
class Config:
    """Manages application configuration."""
    def __init__(self, config_path="config.json"):
        self.config_path = config_path
        self.config = self._load_config()

    def _load_config(self) -> dict:
        """Loads configuration from a JSON file or defaults."""
        try:
            with open(self.config_path, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            # Default configuration
            return {
                "database_url": "sqlite:///legacy_data.db",  # Changed to URL
                "ai_model": "gpt-3.5-turbo",
                "log_file": "legacy_manager.log",
                "secret_key": self._generate_secret_key(),  # Renamed
                "interface_mode": "cli",
                "password_salt": "default_salt" # Added salt
            }

    def _generate_secret_key(self) -> str:
        """Generates a Fernet secret key."""
        return Fernet.generate_key().decode()

    def get(self, key: str) -> Any:
        """Gets a configuration value."""
        return self.config.get(key)

    def set(self, key: str, value: Any) -> None:
        """Sets a configuration value."""
        self.config[key] = value
        self._save_config()

    def _save_config(self) -> None:
        """Saves the configuration to a JSON file."""
        with open(self.config_path, "w") as f:
            json.dump(self.config, f, indent=4)

config = Config()

# Logging
logging.basicConfig(filename=config.get("log_file"), level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)  # Get the logger for this module

# Error Handling
class CustomException(Exception):
    """Base class for custom exceptions."""
    pass

class UserNotFoundException(CustomException):
    """Raised when a user is not found."""
    pass

class LegacyPlanNotFoundException(CustomException):
    """Raised when a legacy plan is not found."""
    pass

class DatabaseException(CustomException):
    """Raised for database-related errors."""
    pass

class EncryptionException(CustomException):
    """Raised for encryption/decryption errors."""
    pass
class InvalidArgumentException(CustomException):
    """Raised for invalid arguments"""
    pass

class ErrorHandler:
    """Handles application errors."""
    @staticmethod
    def handle_exception(e: Exception) -> None:
        """Logs and prints an error message."""
        logger.error(f"An error occurred: {e}")
        print(f"Error: {e}")

# Utility Functions
class Utils:
    """Provides utility functions."""

    @staticmethod
    def generate_uuid() -> str:
        """Generates a UUID."""
        return str(uuid.uuid4())

    @staticmethod
    def get_fernet() -> Fernet:
        """Gets a Fernet instance using the secret key."""
        secret_key = config.get("secret_key")
        if not secret_key:
            raise EncryptionException("Secret key is not configured.")
        try:
            return Fernet(secret_key.encode())
        except Exception as e:
            raise EncryptionException(f"Failed to create Fernet instance: {e}")

    @staticmethod
    def encrypt_data(data: str) -> str:
        """Encrypts data using Fernet."""
        if not data:
            return ""
        fernet = Utils.get_fernet()
        try:
            return fernet.encrypt(data.encode()).decode()
        except Exception as e:
            raise EncryptionException(f"Encryption failed: {e}")

    @staticmethod
    def decrypt_data(encrypted_data: str) -> str:
        """Decrypts data using Fernet."""
        if not encrypted_data:
            return ""
        fernet = Utils.get_fernet()
        try:
            return fernet.decrypt(encrypted_data.encode()).decode()
        except Exception as e:
            raise EncryptionException(f"Decryption failed: {e}")

    @staticmethod
    def format_date(date_obj: datetime.datetime) -> str:
        """Formats a datetime object."""
        return date_obj.strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def hash_password(password: str, salt: str) -> str:
        """Hashes a password using PBKDF2."""
        password_bytes = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password_bytes).hex()

    @staticmethod
    def verify_password(password: str, hashed_password: str, salt: str) -> bool:
        """Verifies a password against its hash."""
        new_hash = Utils.hash_password(password, salt)
        return new_hash == hashed_password

# Data Models (Pydantic)
class Beneficiary(BaseModel):
    """Represents a beneficiary."""
    name: str = Field(..., min_length=1)
    email: EmailStr
    relationship: str = Field(..., min_length=1)

class Document(BaseModel):
    """Represents a document."""
    title: str = Field(..., min_length=1)
    description: str = Field(..., max_length=1000)
    file_path: str = Field(..., min_length=1)  # Store path, not the file itself

class LegacyPlan(BaseModel):
    """Represents a legacy plan."""
    plan_id: str = Field(default_factory=Utils.generate_uuid)
    plan_name: str = Field(..., min_length=1)
    documents: List[Document] = Field(default_factory=list)
    beneficiaries: List[Beneficiary] = Field(default_factory=list)
    creation_date: str = Field(default_factory=lambda: Utils.format_date(datetime.datetime.now()))

class User(BaseModel):
    """Represents a user."""
    user_id: str = Field(default_factory=Utils.generate_uuid)
    username: str = Field(..., min_length=1)
    password: str  # Store hashed password
    email: EmailStr
    legacy_plans: Dict[str, LegacyPlan] = Field(default_factory=dict)
    salt: str # Store the salt.

# Database Management
class DataStorage:
    """Manages data persistence using SQLite."""
    def __init__(self, database_url=config.get("database_url")):
        self.database_url = database_url
        self.conn = None
        self.cursor = None
        self._connect()
        self._create_tables()

    def _connect(self) -> None:
        """Connects to the SQLite database."""
        try:
            self.conn = sqlite3.connect(self.database_url)
            self.cursor = self.conn.cursor()
        except sqlite3.Error as e:
            raise DatabaseException(f"Failed to connect to database: {e}")

    def _disconnect(self) -> None:
        """Disconnects from the SQLite database."""
        if self.conn:
            try:
                self.conn.close()
            except sqlite3.Error as e:
                raise DatabaseException(f"Failed to close database connection: {e}")
            finally:
                self.conn = None
                self.cursor = None

    def _reconnect(self) -> None:
        """Reconnect to the database."""
        self._disconnect()
        self._connect()

    def _create_tables(self) -> None:
        """Creates the necessary database tables."""
        try:
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE,
                    salt TEXT NOT NULL
                )
            """)
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS legacy_plans (
                    plan_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    plan_name TEXT NOT NULL,
                    creation_date TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            """)
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS documents (
                    document_id TEXT PRIMARY KEY,
                    plan_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    FOREIGN KEY (plan_id) REFERENCES legacy_plans(plan_id)
                )
            """)
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS beneficiaries (
                    beneficiary_id TEXT PRIMARY KEY,
                    plan_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    relationship TEXT NOT NULL,
                    FOREIGN KEY (plan_id) REFERENCES legacy_plans(plan_id)
                )
            """)
            self.conn.commit()
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseException(f"Failed to create tables: {e}")

    def get_user(self, user_id: str) -> Optional[User]:
        """Retrieves a user by ID."""
        try:
            self.cursor.execute("SELECT user_id, username, password, email, salt FROM users WHERE user_id = ?", (user_id,))
            row = self.cursor.fetchone()
            if row:
                user_data = {
                    "user_id": row[0],
                    "username": row[1],
                    "password": row[2],
                    "email": row[3],
                    "salt": row[4]
                }
                user = User(**user_data)
                user.legacy_plans = self._get_legacy_plans_for_user(user_id)
                return user
            return None
        except sqlite3.Error as e:
            raise DatabaseException(f"Failed to get user: {e}")

    def get_user_by_username(self, username: str) -> Optional[User]:
        """Retrieves a user by username."""
        try:
            self.cursor.execute("SELECT user_id, username, password, email, salt FROM users WHERE username = ?", (username,))
            row = self.cursor.fetchone()
            if row:
                user_data = {
                    "user_id": row[0],
                    "username": row[1],
                    "password": row[2],
                    "email": row[3],
                    "salt": row[4]
                }
                user = User(**user_data)
                user.legacy_plans = self._get_legacy_plans_for_user(user.user_id)
                return user
            return None
        except sqlite3.Error as e:
            raise DatabaseException(f"Failed to get user by username: {e}")

    def create_user(self, user: User) -> None:
        """Creates a new user."""
        try:
            self.cursor.execute("""
                INSERT INTO users (user_id, username, password, email, salt)
                VALUES (?, ?, ?, ?, ?)
            """, (user.user_id, user.username, user.password, user.email, user.salt))
            self.conn.commit()
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseException(f"Failed to create user: {e}")

    def update_user(self, user: User) -> None:
        """Updates an existing user."""
        try:
            self.cursor.execute("""
                UPDATE users SET username = ?, password = ?, email = ? , salt = ?
                WHERE user_id = ?
            """, (user.username, user.password, user.email, user.salt, user.user_id))
            self.conn.commit()
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseException(f"Failed to update user: {e}")

    def delete_user(self, user_id: str) -> None:
        """Deletes a user."""
        try:
            # Delete related data first (documents, beneficiaries, plans)
            self._delete_legacy_plans_for_user(user_id) # Cascade delete
            self.cursor.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
            self.conn.commit()
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseException(f"Failed to delete user: {e}")

    def _get_legacy_plans_for_user(self, user_id: str) -> Dict[str, LegacyPlan]:
        """Retrieves all legacy plans for a user."""
        try:
            self.cursor.execute("SELECT plan_id, plan_name, creation_date FROM legacy_plans WHERE user_id = ?", (user_id,))
            plans_data = self.cursor.fetchall()
            plans: Dict[str, LegacyPlan] = {}
            for plan_data in plans_data:
                plan_id = plan_data[0]
                # Get documents and beneficiaries for the plan
                documents = self._get_documents_for_plan(plan_id)
                beneficiaries = self._get_beneficiaries_for_plan(plan_id)
                plan = LegacyPlan(
                    plan_id=plan_id,
                    plan_name=plan_data[1],
                    creation_date=plan_data[2],
                    documents=documents,
                    beneficiaries=beneficiaries
                )
                plans[plan_id] = plan
            return plans
        except sqlite3.Error as e:
            raise DatabaseException(f"Failed to get legacy plans: {e}")

    def get_legacy_plan(self, plan_id: str) -> Optional[LegacyPlan]:
        """Retrieves a legacy plan by ID."""
        try:
            self.cursor.execute("SELECT plan_id, user_id, plan_name, creation_date FROM legacy_plans WHERE plan_id = ?", (plan_id,))
            row = self.cursor.fetchone()
            if row:
                documents = self._get_documents_for_plan(plan_id)
                beneficiaries = self._get_beneficiaries_for_plan(plan_id)
                return LegacyPlan(
                    plan_id=row[0],
                    plan_name=row[2],
                    documents=documents,
                    beneficiaries=beneficiaries,
                    creation_date=row[3]
                )
            return None
        except sqlite3.Error as e:
            raise DatabaseException(f"Failed to get legacy plan: {e}")

    def create_legacy_plan(self, plan: LegacyPlan, user_id: str) -> None:
        """Creates a new legacy plan."""
        try:
            self.cursor.execute("""
                INSERT INTO legacy_plans (plan_id, user_id, plan_name, creation_date)
                VALUES (?, ?, ?, ?)
            """, (plan.plan_id, user_id, plan.plan_name, plan.creation_date))

            # Create documents and beneficiaries
            for document in plan.documents:
                self._create_document(document, plan.plan_id)
            for beneficiary in plan.beneficiaries:
                self._create_beneficiary(beneficiary, plan.plan_id)

            self.conn.commit()
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseException(f"Failed to create legacy plan: {e}")

    def update_legacy_plan(self, plan: LegacyPlan) -> None:
        """Updates an existing legacy plan."""
        try:
            self.cursor.execute("""
                UPDATE legacy_plans SET plan_name = ?
                WHERE plan_id = ?
            """, (plan.plan_name, plan.plan_id))

            # Update documents and beneficiaries (simplified - delete and recreate)
            self._delete_documents_for_plan(plan.plan_id)
            self._delete_beneficiaries_for_plan(plan.plan_id)
            for document in plan.documents:
                self._create_document(document, plan.plan_id)
            for beneficiary in plan.beneficiaries:
                self._create_beneficiary(beneficiary, plan.plan_id)

            self.conn.commit()
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseException(f"Failed to update legacy plan: {e}")

    def delete_legacy_plan(self, plan_id: str) -> None:
        """Deletes a legacy plan."""
        try:
            # Delete associated documents and beneficiaries first
            self._delete_documents_for_plan(plan_id)
            self._delete_beneficiaries_for_plan(plan_id)
            self.cursor.execute("DELETE FROM legacy_plans WHERE plan_id = ?", (plan_id,))
            self.conn.commit()
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseException(f"Failed to delete legacy plan: {e}")

    def _delete_legacy_plans_for_user(self, user_id: str) -> None:
        """Deletes all legacy plans for a user."""
        try:
            # IMPORTANT:  Delete documents and beneficiaries associated with the plans first.
            self.cursor.execute("SELECT plan_id FROM legacy_plans WHERE user_id = ?", (user_id,))
            plan_ids = [row[0] for row in self.cursor.fetchall()]
            for plan_id in plan_ids:
                self._delete_documents_for_plan(plan_id)
                self._delete_beneficiaries_for_plan(plan_id)
            self.cursor.execute("DELETE FROM legacy_plans WHERE user_id = ?", (user_id,))
            self.conn.commit()
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseException(f"Failed to delete legacy plans for user: {e}")

    def _get_documents_for_plan(self, plan_id: str) -> List[Document]:
        """Retrieves all documents for a legacy plan."""
        try:
            self.cursor.execute("SELECT document_id, title, description, file_path FROM documents WHERE plan_id = ?", (plan_id,))
            rows = self.cursor.fetchall()
            return [Document(title=row[1], description=row[2], file_path=row[3]) for row in rows]
        except sqlite3.Error as e:
            raise DatabaseException(f"Failed to get documents: {e}")

    def _create_document(self, document: Document, plan_id: str) -> None:
        """Creates a new document."""
        try:
            document_id = Utils.generate_uuid()
            self.cursor.execute("""
                INSERT INTO documents (document_id, plan_id, title, description, file_path)
                VALUES (?, ?, ?, ?, ?)
            """, (document_id, plan_id, document.title, document.description, document.file_path))
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseException(f"Failed to create document: {e}")

    def _delete_documents_for_plan(self, plan_id: str) -> None:
        """Deletes all documents for a plan."""
        try:
            self.cursor.execute("DELETE FROM documents WHERE plan_id = ?", (plan_id,))
            self.conn.commit()
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseException(f"Failed to delete documents for plan: {e}")

    def _get_beneficiaries_for_plan(self, plan_id: str) -> List[Beneficiary]:
        """Retrieves all beneficiaries for a legacy plan."""
        try:
            self.cursor.execute("SELECT beneficiary_id, name, email, relationship FROM beneficiaries WHERE plan_id = ?", (plan_id,))
            rows = self.cursor.fetchall()
            return [Beneficiary(name=row[1], email=row[2], relationship=row[3]) for row in rows]
        except sqlite3.Error as e:
            raise DatabaseException(f"Failed to get beneficiaries: {e}")

    def _create_beneficiary(self, beneficiary: Beneficiary, plan_id: str) -> None:
        """Creates a new beneficiary."""
        try:
            beneficiary_id = Utils.generate_uuid()
            self.cursor.execute("""
                INSERT INTO beneficiaries (beneficiary_id, plan_id, name, email, relationship)
                VALUES (?, ?, ?, ?, ?)
            """, (beneficiary_id, plan_id, beneficiary.name, beneficiary.email, beneficiary.relationship))
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseException(f"Failed to create beneficiary: {e}")

    def _delete_beneficiaries_for_plan(self, plan_id: str) -> None:
        """Deletes all beneficiaries for a plan."""
        try:
            self.cursor.execute("DELETE FROM beneficiaries WHERE plan_id = ?", (plan_id,))
            self.conn.commit()
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseException(f"Failed to delete beneficiaries for plan: {e}")

    def __del__(self):
        """Ensures the database connection is closed when the object is destroyed."""
        self._disconnect()

data_store = DataStorage()

# User Management
class UserManagement:
    """Handles user authentication and management."""
    def __init__(self, data_store: DataStorage):
        self.data_store = data_store

    def create_user(self, username: str, password: str, email: str) -> User:
        """Creates a new user."""
        if not username or not password or not email:
            raise InvalidArgumentException("Username, password, and email are required.")
        if self.data_store.get_user_by_username(username):
            raise CustomException(f"User with username {username} already exists.")

        salt = config.get("password_salt") # Use the salt from config
        hashed_password = Utils.hash_password(password, salt)
        user = User(username=username, password=hashed_password, email=email, salt=salt)
        self.data_store.create_user(user)
        logger.info(f"User created: {user.user_id}, {username}, {email}")
        return user

    def authenticate_user(self, username: str, password: str) -> User:
        """Authenticates a user."""
        user = self.data_store.get_user_by_username(username)
        if not user:
            raise UserNotFoundException(f"User with username {username} not found.")

        if not Utils.verify_password(password, user.password, user.salt):
            raise CustomException("Invalid password.")
        logger.info(f"User authenticated: {user.user_id}")
        return user

    def get_user_profile(self, user_id: str) -> User:
        """Retrieves a user profile."""
        user = self.data_store.get_user(user_id)
        if not user:
            raise UserNotFoundException(f"User with ID {user_id} not found.")
        return user

    def update_user_profile(self, user_id: str, username: str, email: str) -> User:
        """Updates a user's profile."""
        user = self.data_store.get_user(user_id)
        if not user:
            raise UserNotFoundException(f"User with ID {user_id} not found.")

        # check if the new username is already taken.
        existing_user_by_name = self.data_store.get_user_by_username(username)
        if existing_user_by_name and existing_user_by_name.user_id != user_id:
            raise CustomException(f"Username {username} is already taken.")
        user.username = username
        user.email = email
        self.data_store.update_user(user)
        logger.info(f"User profile updated: {user_id}, {username}, {email}")
        return user

    def update_user_password(self, user_id: str, new_password: str) -> User:
        """Updates a user's password."""
        user = self.data_store.get_user(user_id)
        if not user:
            raise UserNotFoundException(f"User with ID {user_id} not found.")
        salt = config.get("password_salt")
        hashed_password = Utils.hash_password(new_password, salt)
        user.password = hashed_password
        user.salt = salt # Make sure to update the salt.
        self.data_store.update_user(user)
        logger.info(f"User password updated: {user.user_id}")
        return user

    def delete_user(self, user_id: str) -> None:
        """Deletes a user."""
        user = self.data_store.get_user(user_id)
        if not user:
            raise UserNotFoundException(f"User with ID {user_id} not found.")
        self.data_store.delete_user(user_id)
        logger.info(f"User deleted: {user_id}")

user_manager = UserManagement(data_store)

# Legacy Planning
class LegacyPlanning:
    """Handles legacy plan creation and management."""
    def __init__(self, data_store: DataStorage):
        self.data_store = data_store

    def create_legacy_plan(self, user_id: str, plan_name: str, documents: List[Document], beneficiaries: List[Beneficiary]) -> LegacyPlan:
        """Creates a new legacy plan."""
        user = self.data_store.get_user(user_id)
        if not user:
            raise UserNotFoundException(f"User with ID {user_id} not found.")
        if not plan_name:
            raise InvalidArgumentException("Plan name is required.")

        plan = LegacyPlan(plan_name=plan_name, documents=documents, beneficiaries=beneficiaries)
        self.data_store.create_legacy_plan(plan, user_id)
        logger.info(f"Legacy plan created: {plan.plan_id} for user {user_id}")
        return plan

    def get_legacy_plan(self, plan_id: str) -> LegacyPlan:
        """Retrieves a legacy plan by ID."""
        plan = self.data_store.get_legacy_plan(plan_id)
        if not plan:
            raise LegacyPlanNotFoundException(f"Legacy plan with ID {plan_id} not found.")
        return plan

    def update_legacy_plan(self, plan_id: str, plan_name: str, documents: List[Document], beneficiaries: List[Beneficiary]) -> LegacyPlan:
        """Updates an existing legacy plan."""
        plan = self.data_store.get_legacy_plan(plan_id)
        if not plan:
            raise LegacyPlanNotFoundException(f"Legacy plan with ID {plan_id} not found.")
        if not plan_name:
            raise InvalidArgumentException("Plan name is required.")
        plan.plan_name = plan_name
        plan.documents = documents
        plan.beneficiaries = beneficiaries
        self.data_store.update_legacy_plan(plan)
        logger.info(f"Legacy plan updated: {plan_id}")
        return plan

    def delete_legacy_plan(self, plan_id: str) -> None:
        """Deletes a legacy plan."""
        plan = self.data_store.get_legacy_plan(plan_id)
        if not plan:
            raise LegacyPlanNotFoundException(f"Legacy plan with ID {plan_id} not found.")
        self.data_store.delete_legacy_plan(plan_id)
        logger.info(f"Legacy plan deleted: {plan_id}")

legacy_planner = LegacyPlanning(data_store)

# AI Integration (Placeholder)
class AIIntegration:
    """Integrates with AI models for NLP and task automation."""
    def __init__(self, model_name=config.get("ai_model")):
        self.model_name = model_name

    def process_text(self, text: str) -> str:
        """Processes text using the AI model."""
        # Placeholder for AI processing logic
        return f"AI processed: {text} using {self.model_name}"

ai_integrator = AIIntegration()

# Task Automation (Placeholder)
class TaskAutomation:
    """Automates legacy-related tasks."""
    def distribute_documents(self, documents: List[Document], beneficiaries: List[Beneficiary]) -> bool:
        """Distributes documents to beneficiaries."""
        # Placeholder for document distribution logic
        logger.info(f"Distributing documents to {beneficiaries}")
        print(f"Distributing documents: {documents} to beneficiaries: {beneficiaries}")
        return True

    def manage_accounts(self, accounts: List[str]) -> bool:
        """Manages digital accounts."""
        # Placeholder for account management logic
        logger.info(f"Managing accounts: {accounts}")
        print(f"Managing accounts: {accounts}")
        return True

task_automator = TaskAutomation()

# Interaction
class Interaction:
    """Manages user interactions (CLI and potential web)."""
    def __init__(self, user_manager: UserManagement, legacy_planner: LegacyPlanning,
                 ai_integrator: AIIntegration, task_automator: TaskAutomation,
                 mode=config.get("interface_mode")):
        self.user_manager = user_manager
        self.legacy_planner = legacy_planner
        self.ai_integrator = ai_integrator
        self.task_automator = task_automator
        self.mode = mode

    def run(self) -> None:
        """Runs the interaction interface."""
        if self.mode == "cli":
            self.run_cli()
        else:
            print("Web interface not implemented yet.")

    def run_cli(self) -> None:
        """Runs the command-line interface."""
        while True:
            command = input("Enter command (or 'help'): ")
            try:
                if command == "help":
                    self.display_help()
                elif command == "create_user":
                    self.handle_create_user()
                elif command == "login":
                    self.handle_login()
                elif command == "exit":
                    break
                else:
                    print("Invalid command. Type 'help' to see available commands.")
            except CustomException as e:
                ErrorHandler.handle_exception(e)

    def display_help(self) -> None:
        """Displays available commands."""
        print("\nAvailable commands:")
        print("  help        - Display this help message")
        print("  create_user - Create a new user")
        print("  login       - Log in to an existing user account")
        print("  exit        - Exit the application")
        print("\nUser commands (after login):")
        print("  create_plan - Create a new legacy plan")
        print("  get_plan    - Retrieve a legacy plan")
        print("  update_plan   - Update a legacy plan")
        print("  delete_plan   - Delete a legacy plan")
        print("  profile     - View your user profile")
        print("  update_profile  - Update your user profile")
        print("  update_password - Update your password")
        print("  delete_user     - Delete your user account")
        print("  process_text - Process text with AI")
        print("  distribute    - Distribute documents (test)")
        print("  user_exit   - Exit user mode")

    def handle_create_user(self) -> None:
        """Handles user creation."""
        username = input("Username: ")
        password = input("Password: ")
        email = input("Email: ")
        try:
            user = user_manager.create_user(username, password, email)
            print(f"User created with ID: {user.user_id}")
        except ValidationError as e:
            print(f"Validation Error: {e}")

    def handle_login(self) -> None:
        """Handles user login."""
        username = input("Username: ")
        password = input("Password: ")
        try:
            user = user_manager.authenticate_user(username, password)
            print(f"Logged in as user ID: {user.user_id}")
            self.handle_user_commands(user.user_id)
        except CustomException as e:
            ErrorHandler.handle_exception(e)

    def handle_user_commands(self, user_id: str) -> None:
        """Handles commands for a logged-in user."""
        while True:
            command = input("Enter user command (or 'help'): ")
            try:
                if command == "help":
                    self.display_help()
                elif command == "create_plan":
                    self.handle_create_plan(user_id)
                elif command == "get_plan":
                    self.handle_get_plan(user_id)
                elif command == "update_plan":
                    self.handle_update_plan(user_id)
                elif command == "delete_plan":
                    self.handle_delete_plan(user_id)
                elif command == "profile":
                    self.handle_get_profile(user_id)
                elif command == "update_profile":
                    self.handle_update_profile(user_id)
                elif command == "update_password":
                    self.handle_update_password(user_id)
                elif command == "delete_user":
                    self.handle_delete_user(user_id)
                elif command == "process_text":
                    self.handle_process_text()
                elif command == "distribute":
                    self.handle_distribute()
                elif command == "user_exit":
                    break
                else:
                    print("Invalid user command. Type 'help' to see available commands.")
            except CustomException as e:
                ErrorHandler.handle_exception(e)

    def handle_create_plan(self, user_id: str) -> None:
        """Handles legacy plan creation."""
        plan_name = input("Plan Name: ")
        documents = self.handle_documents_input()
        beneficiaries = self.handle_beneficiaries_input()
        try:
            plan = legacy_planner.create_legacy_plan(user_id, plan_name, documents, beneficiaries)
            print(f"Legacy plan created with ID: {plan.plan_id}")
        except ValidationError as e:
            print(f"Validation Error: {e}")

    def handle_get_plan(self, user_id: str) -> None:
        """Handles legacy plan retrieval."""
        plan_id = input("Plan ID: ")
        try:
            plan = legacy_planner.get_legacy_plan(plan_id)
            print(plan.model_dump_json(indent=2))  # Use pydantic's model_dump_json
        except CustomException as e:
            ErrorHandler.handle_exception(e)

    def handle_update_plan(self, user_id: str) -> None:
        """Handles legacy plan updates."""
        plan_id = input("Plan ID to update: ")
        plan_name = input("New Plan Name: ")
        documents = self.handle_documents_input()
        beneficiaries = self.handle_beneficiaries_input()
        try:
            updated_plan = legacy_planner.update_legacy_plan(plan_id, plan_name, documents, beneficiaries)
            print(f"Legacy plan updated: {updated_plan.plan_id}")
        except ValidationError as e:
            print(f"Validation Error: {e}")
        except CustomException as e:
            ErrorHandler.handle_exception(e)

    def handle_delete_plan(self, user_id: str) -> None:
        """Handles legacy plan deletion"""
        plan_id = input("Plan ID to delete: ")
        try:
            legacy_planner.delete_legacy_plan(plan_id)
            print(f"Legacy plan deleted: {plan_id}")
        except CustomException as e:
            ErrorHandler.handle_exception(e)

    def handle_get_profile(self, user_id: str) -> None:
        """Handles user profile retrieval."""
        try:
            user = user_manager.get_user_profile(user_id)
            print(user.model_dump_json(indent=2))
        except CustomException as e:
            ErrorHandler.handle_exception(e)

    def handle_update_profile(self, user_id: str) -> None:
        """Handles user profile updates."""
        username = input("New Username: ")
        email = input("New Email: ")
        try:
            updated_user = user_manager.update_user_profile(user_id, username, email)
            print(f"User profile updated: {updated_user.user_id}")
        except ValidationError as e:
            print(f"Validation Error: {e}")
        except CustomException as e:
            ErrorHandler.handle_exception(e)

    def handle_update_password(self, user_id: str) -> None:
        """Handles user password updates."""
        new_password = input("New Password: ")
        try:
            updated_user = user_manager.update_user_password(user_id, new_password)
            print(f"User password updated for user: {updated_user.user_id}")
        except CustomException as e:
            ErrorHandler.handle_exception(e)

    def handle_delete_user(self, user_id: str) -> None:
        """Handles user deletion."""
        confirm = input(f"Are you sure you want to delete user ID {user_id}? (yes/no): ")
        if confirm.lower() == "yes":
            user_manager.delete_user(user_id)
            print(f"User deleted: {user_id}")
            return # Exit user mode after deletion
        else:
            print("User deletion cancelled.")

    def handle_process_text(self) -> None:
        """Handles text processing using AI."""
        text = input("Enter text to process: ")
        result = ai_integrator.process_text(text)
        print(result)

    def handle_distribute(self) -> None:
        """Handles document distribution (test)."""
        docs = self.handle_documents_input()
        bens = self.handle_beneficiaries_input()
        task_automator.distribute_documents(docs, bens)
        print("Documents distributed (test).")

    def handle_documents_input(self) -> List[Document]:
        """Handles document input from the user."""
        documents: List[Document] = []
        while True:
            title = input("Document Title (or 'done'): ")
            if title.lower() == 'done':
                break
            description = input("Document Description: ")
            file_path = input("Document File Path: ")
            try:
                document = Document(title=title, description=description, file_path=file_path)
                documents.append(document)
            except ValidationError as e:
                print(f"Invalid document input: {e}")
        return documents

    def handle_beneficiaries_input(self) -> List[Beneficiary]:
        """Handles beneficiary input from the user."""
        beneficiaries: List[Beneficiary] = []
        while True:
            name = input("Beneficiary Name (or 'done'): ")
            if name.lower() == 'done':
                break
            email = input("Beneficiary Email: ")
            relationship = input("Beneficiary Relationship: ")
            try:
                beneficiary = Beneficiary(name=name, email=email, relationship=relationship)
                beneficiaries.append(beneficiary)
            except ValidationError as e:
                print(f"Invalid beneficiary input: {e}")
        return beneficiaries

# Main Execution
if __name__ == "__main__":
    try:
        interaction = Interaction(user_manager, legacy_planner, ai_integrator, task_automator)
        interaction.run()
    except Exception as e:
        ErrorHandler.handle_exception(e)

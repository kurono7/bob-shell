"""
Secure Login Module - Fixed SQL Injection Vulnerabilities
This module provides secure authentication using parameterized queries
"""

import secrets
import hashlib
from typing import Optional, Tuple
from datetime import datetime, timedelta
import logging
import sys
import os

# Add parent directory to path to import database module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db_manager import DatabaseManager

# Configure secure logging (no sensitive data)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
MAX_FAILED_ATTEMPTS = 5
ACCOUNT_LOCKOUT_DURATION = timedelta(minutes=15)
SESSION_DURATION = timedelta(hours=24)
MIN_USERNAME_LENGTH = 3
MIN_PASSWORD_LENGTH = 8


class AuthenticationError(Exception):
    """Base exception for authentication errors"""
    pass


class AccountLockedError(AuthenticationError):
    """Raised when account is locked due to too many failed attempts"""
    pass


class InvalidCredentialsError(AuthenticationError):
    """Raised when credentials are invalid"""
    pass


class PasswordValidator:
    """Validates password strength and requirements"""
    
    @staticmethod
    def validate(password: str) -> Tuple[bool, str]:
        """
        Validate password meets security requirements.
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if len(password) < MIN_PASSWORD_LENGTH:
            return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
        
        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
        
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
        
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit"
        
        return True, ""


class PasswordHasher:
    """Handles secure password hashing using SHA-256 with salt"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash password securely using SHA-256 with random salt.
        
        Note: In production, use bcrypt or argon2 instead.
        This uses SHA-256 for demo purposes to avoid external dependencies.
        
        Args:
            password: Plain text password
            
        Returns:
            Hashed password with salt (format: salt$hash)
        """
        salt = secrets.token_hex(16)
        password_hash = hashlib.sha256((salt + password).encode()).hexdigest()
        return f"{salt}${password_hash}"
    
    @staticmethod
    def verify_password(password: str, stored_hash: str) -> bool:
        """
        Verify password against stored hash.
        
        Args:
            password: Plain text password to verify
            stored_hash: Stored hash in format salt$hash
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            salt, expected_hash = stored_hash.split('$')
            password_hash = hashlib.sha256((salt + password).encode()).hexdigest()
            return password_hash == expected_hash
        except (ValueError, AttributeError):
            return False


class SessionManager:
    """Manages user sessions securely"""
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize session manager.
        
        Args:
            db_manager: Database manager instance
        """
        self.db = db_manager
    
    def create_session(self, user_id: int) -> str:
        """
        Create a new session for user.
        
        Args:
            user_id: User ID
            
        Returns:
            Session token
        """
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + SESSION_DURATION
        
        # SECURE: Using parameterized query
        query = """
            INSERT INTO sessions (token, user_id, expires_at)
            VALUES (?, ?, ?)
        """
        self.db.execute_query(query, (token, user_id, expires_at.isoformat()))
        
        logger.info(f"Session created for user_id: {user_id}")
        return token
    
    def validate_session(self, token: str) -> Optional[int]:
        """
        Validate session token and return user_id if valid.
        
        Args:
            token: Session token to validate
            
        Returns:
            User ID if session is valid, None otherwise
        """
        # SECURE: Using parameterized query
        query = """
            SELECT user_id, expires_at FROM sessions
            WHERE token = ?
        """
        results = self.db.execute_query(query, (token,))
        
        if not results:
            return None
        
        user_id, expires_at_str = results[0]
        expires_at = datetime.fromisoformat(expires_at_str)
        
        if datetime.now() > expires_at:
            self.delete_session(token)
            return None
        
        return user_id
    
    def delete_session(self, token: str) -> None:
        """
        Delete a session.
        
        Args:
            token: Session token to delete
        """
        # SECURE: Using parameterized query
        query = "DELETE FROM sessions WHERE token = ?"
        self.db.execute_query(query, (token,))
        logger.info("Session deleted")


class LoginAttemptTracker:
    """Tracks and manages failed login attempts"""
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize login attempt tracker.
        
        Args:
            db_manager: Database manager instance
        """
        self.db = db_manager
    
    def is_account_locked(self, username: str) -> bool:
        """
        Check if account is locked due to failed attempts.
        
        Args:
            username: Username to check
            
        Returns:
            True if account is locked, False otherwise
        """
        # SECURE: Using parameterized query
        query = """
            SELECT failed_attempts, last_failed_attempt
            FROM login_attempts
            WHERE username = ?
        """
        results = self.db.execute_query(query, (username,))
        
        if not results:
            return False
        
        failed_attempts, last_failed_str = results[0]
        
        if failed_attempts < MAX_FAILED_ATTEMPTS:
            return False
        
        last_failed = datetime.fromisoformat(last_failed_str)
        lockout_expires = last_failed + ACCOUNT_LOCKOUT_DURATION
        
        if datetime.now() > lockout_expires:
            self.reset_attempts(username)
            return False
        
        return True
    
    def record_failed_attempt(self, username: str) -> None:
        """
        Record a failed login attempt.
        
        Args:
            username: Username that failed login
        """
        now = datetime.now().isoformat()
        
        # SECURE: Using parameterized query
        query = """
            INSERT INTO login_attempts (username, failed_attempts, last_failed_attempt)
            VALUES (?, 1, ?)
            ON CONFLICT(username) DO UPDATE SET
                failed_attempts = failed_attempts + 1,
                last_failed_attempt = ?
        """
        self.db.execute_query(query, (username, now, now))
        logger.warning(f"Failed login attempt recorded for username (length: {len(username)})")
    
    def reset_attempts(self, username: str) -> None:
        """
        Reset failed login attempts for user.
        
        Args:
            username: Username to reset
        """
        # SECURE: Using parameterized query
        query = "DELETE FROM login_attempts WHERE username = ?"
        self.db.execute_query(query, (username,))


class UserRepository:
    """Repository for user data access"""
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize user repository.
        
        Args:
            db_manager: Database manager instance
        """
        self.db = db_manager
    
    def find_by_username(self, username: str) -> Optional[Tuple[int, str, str]]:
        """
        Find user by username.
        
        Args:
            username: Username to search for
            
        Returns:
            Tuple of (user_id, username, password_hash) if found, None otherwise
        """
        # SECURE: Using parameterized query
        query = """
            SELECT id, username, password_hash
            FROM users
            WHERE username = ?
        """
        results = self.db.execute_query(query, (username,))
        
        if not results:
            return None
        
        return results[0]
    
    def create_user(self, username: str, password_hash: str) -> int:
        """
        Create a new user.
        
        Args:
            username: Username
            password_hash: Hashed password
            
        Returns:
            User ID of created user
        """
        # SECURE: Using parameterized query
        query = """
            INSERT INTO users (username, password_hash)
            VALUES (?, ?)
        """
        self.db.execute_query(query, (username, password_hash))
        
        # Get the created user's ID
        user = self.find_by_username(username)
        if user:
            logger.info(f"User created: {username}")
            return user[0]
        
        raise Exception("Failed to create user")


class AuthenticationService:
    """
    Service for user authentication operations.
    
    Follows Single Responsibility Principle - only handles authentication logic.
    Uses dependency injection for database access.
    """
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize authentication service.
        
        Args:
            db_manager: Database manager instance for dependency injection
        """
        self.user_repo = UserRepository(db_manager)
        self.session_manager = SessionManager(db_manager)
        self.attempt_tracker = LoginAttemptTracker(db_manager)
        self.password_hasher = PasswordHasher()
        self.password_validator = PasswordValidator()
    
    def login(self, username: str, password: str) -> str:
        """
        Authenticate user and create session.
        
        Args:
            username: Username
            password: Plain text password
            
        Returns:
            Session token
            
        Raises:
            AccountLockedError: If account is locked
            InvalidCredentialsError: If credentials are invalid
        """
        # Input validation
        if not username or not password:
            raise InvalidCredentialsError("Username and password are required")
        
        if len(username) < MIN_USERNAME_LENGTH:
            raise InvalidCredentialsError("Invalid username")
        
        # Check if account is locked
        if self.attempt_tracker.is_account_locked(username):
            logger.warning(f"Login attempt on locked account (username length: {len(username)})")
            raise AccountLockedError("Account is temporarily locked due to too many failed attempts")
        
        # Find user - SECURE: using parameterized query in repository
        user = self.user_repo.find_by_username(username)
        
        if not user:
            self.attempt_tracker.record_failed_attempt(username)
            raise InvalidCredentialsError("Invalid username or password")
        
        user_id, stored_username, password_hash = user
        
        # Verify password
        if not self.password_hasher.verify_password(password, password_hash):
            self.attempt_tracker.record_failed_attempt(username)
            raise InvalidCredentialsError("Invalid username or password")
        
        # Reset failed attempts on successful login
        self.attempt_tracker.reset_attempts(username)
        
        # Create session
        token = self.session_manager.create_session(user_id)
        
        logger.info(f"Successful login for user_id: {user_id}")
        return token
    
    def register(self, username: str, password: str) -> int:
        """
        Register a new user.
        
        Args:
            username: Username
            password: Plain text password
            
        Returns:
            User ID of created user
            
        Raises:
            ValueError: If validation fails
        """
        # Input validation
        if not username or not password:
            raise ValueError("Username and password are required")
        
        if len(username) < MIN_USERNAME_LENGTH:
            raise ValueError(f"Username must be at least {MIN_USERNAME_LENGTH} characters")
        
        # Validate password strength
        is_valid, error_message = self.password_validator.validate(password)
        if not is_valid:
            raise ValueError(error_message)
        
        # Check if username already exists
        existing_user = self.user_repo.find_by_username(username)
        if existing_user:
            raise ValueError("Username already exists")
        
        # Hash password
        password_hash = self.password_hasher.hash_password(password)
        
        # Create user - SECURE: using parameterized query in repository
        user_id = self.user_repo.create_user(username, password_hash)
        
        return user_id
    
    def logout(self, token: str) -> None:
        """
        Logout user by deleting session.
        
        Args:
            token: Session token
        """
        self.session_manager.delete_session(token)
        logger.info("User logged out")
    
    def validate_session(self, token: str) -> Optional[int]:
        """
        Validate session token.
        
        Args:
            token: Session token
            
        Returns:
            User ID if session is valid, None otherwise
        """
        return self.session_manager.validate_session(token)


# Factory function for creating authentication service
def create_auth_service(db_path: str = "banking_app.db") -> AuthenticationService:
    """
    Factory function to create authentication service with dependencies.
    
    Args:
        db_path: Path to database file
        
    Returns:
        Configured AuthenticationService instance
    """
    db_manager = DatabaseManager(db_path)
    return AuthenticationService(db_manager)


# Made with Bob
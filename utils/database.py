import sqlite3
import asyncio
import logging
from datetime import datetime
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self, db_path='database/user_system.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database with all required tables"""
        conn = sqlite3.connect(self.db_path)
        
        # Create users table (already exists)
        conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            display_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create contacts table
        conn.execute('''
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY,
            owner_email TEXT NOT NULL,
            contact_email TEXT NOT NULL,
            nickname TEXT,
            list_type TEXT DEFAULT 'FL',
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_email) REFERENCES users (email),
            UNIQUE(owner_email, contact_email, list_type)
        )
        ''')
        
        # Create sessions table
        conn.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY,
            email TEXT NOT NULL,
            session_id TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'NLN',
            FOREIGN KEY (email) REFERENCES users (email)
        )
        ''')
        
        # Create message history table
        conn.execute('''
        CREATE TABLE IF NOT EXISTS message_history (
            id INTEGER PRIMARY KEY,
            from_email TEXT NOT NULL,
            to_email TEXT NOT NULL,
            message TEXT NOT NULL,
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (from_email) REFERENCES users (email),
            FOREIGN KEY (to_email) REFERENCES users (email)
        )
        ''')
        
        conn.commit()
        conn.close()
        logger.info('Database initialized')
    
    async def get_user_by_email(self, email: str) -> Optional[Dict]:
        """Get user by email"""
        def _get_user():
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            user = cursor.fetchone()
            conn.close()
            
            return dict(user) if user else None
        
        return await asyncio.get_event_loop().run_in_executor(None, _get_user)
    
    async def create_user(self, email: str, password: str, display_name: str = None) -> bool:
        """Create a new user"""
        def _create_user():
            try:
                conn = sqlite3.connect(self.db_path)
                conn.execute(
                    'INSERT INTO users (email, password, display_name) VALUES (?, ?, ?)',
                    (email, password, display_name or email)
                )
                conn.commit()
                conn.close()
                return True
            except sqlite3.IntegrityError:
                return False
        
        return await asyncio.get_event_loop().run_in_executor(None, _create_user)
    
    async def get_user_contacts(self, email: str) -> List[Dict]:
        """Get user's contact list"""
        def _get_contacts():
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT contact_email as email, nickname, list_type 
                FROM contacts 
                WHERE owner_email = ?
            ''', (email,))
            
            contacts = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return contacts
        
        return await asyncio.get_event_loop().run_in_executor(None, _get_contacts)
    
    async def add_contact(self, owner_email: str, contact_email: str, nickname: str, list_type: str = 'FL'):
        """Add a contact to user's list"""
        def _add_contact():
            try:
                conn = sqlite3.connect(self.db_path)
                conn.execute('''
                    INSERT INTO contacts (owner_email, contact_email, nickname, list_type)
                    VALUES (?, ?, ?, ?)
                ''', (owner_email, contact_email, nickname, list_type))
                conn.commit()
                conn.close()
                return True
            except sqlite3.IntegrityError:
                return False  # Contact already exists
        
        return await asyncio.get_event_loop().run_in_executor(None, _add_contact)
    
    async def remove_contact(self, owner_email: str, contact_email: str, list_type: str = 'FL'):
        """Remove a contact from user's list"""
        def _remove_contact():
            conn = sqlite3.connect(self.db_path)
            conn.execute('''
                DELETE FROM contacts 
                WHERE owner_email = ? AND contact_email = ? AND list_type = ?
            ''', (owner_email, contact_email, list_type))
            conn.commit()
            conn.close()
        
        return await asyncio.get_event_loop().run_in_executor(None, _remove_contact)
    
    async def save_message(self, from_email: str, to_email: str, message: str):
        """Save message to history"""
        def _save_message():
            conn = sqlite3.connect(self.db_path)
            conn.execute('''
                INSERT INTO message_history (from_email, to_email, message)
                VALUES (?, ?, ?)
            ''', (from_email, to_email, message))
            conn.commit()
            conn.close()
        
        return await asyncio.get_event_loop().run_in_executor(None, _save_message)
    
    async def create_session(self, email: str, session_id: str):
        """Create a new session"""
        def _create_session():
            conn = sqlite3.connect(self.db_path)
            conn.execute('''
                INSERT INTO sessions (email, session_id)
                VALUES (?, ?)
            ''', (email, session_id))
            conn.commit()
            conn.close()
        
        return await asyncio.get_event_loop().run_in_executor(None, _create_session)
    
    async def update_session_activity(self, session_id: str):
        """Update session last activity"""
        def _update_activity():
            conn = sqlite3.connect(self.db_path)
            conn.execute('''
                UPDATE sessions 
                SET last_activity = CURRENT_TIMESTAMP 
                WHERE session_id = ?
            ''', (session_id,))
            conn.commit()
            conn.close()
        
        return await asyncio.get_event_loop().run_in_executor(None, _update_activity)
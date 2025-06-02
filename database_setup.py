#!/usr/bin/env python3
"""
Database setup and user management for MSN Messenger Server
"""

import sqlite3
import os
import logging

def setup_database():
    """Setup the MSN Messenger database with sample data"""
    
    # Create database directory
    if not os.path.exists('database'):
        os.makedirs('database')
        print("✅ Created database directory")
    
    # Connect to database
    conn = sqlite3.connect('database/msn_messenger.db')
    cursor = conn.cursor()
    
    # Drop existing tables (for fresh setup)
    cursor.execute("DROP TABLE IF EXISTS messages")
    cursor.execute("DROP TABLE IF EXISTS contacts") 
    cursor.execute("DROP TABLE IF EXISTS users")
    
    # Create users table
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            display_name TEXT,
            status TEXT DEFAULT 'NLN',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create contacts table
    cursor.execute('''
        CREATE TABLE contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            contact_email TEXT,
            contact_name TEXT,
            list_type TEXT DEFAULT 'FL',
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create messages table
    cursor.execute('''
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user TEXT,
            to_user TEXT,
            message TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert sample users (matching Wireshark captures)
    sample_users = [
        ('aquaboxs34@hotmail.com', 'password123', 'AquaBoxs'),
        ('testuser@hotmail.com', 'test123', 'Test User'),
        ('friend1@hotmail.com', 'friend123', 'Friend One'),
        ('buddy@msn.com', 'buddy123', 'My Buddy'),
        ('contact@example.com', 'contact123', 'Example Contact')
    ]
    
    for email, password, display_name in sample_users:
        cursor.execute("""
            INSERT INTO users (email, password, display_name) 
            VALUES (?, ?, ?)
        """, (email, password, display_name))
        print(f"✅ Added user: {email}")
    
    # Add sample contacts for aquaboxs34@hotmail.com
    main_user_id = cursor.execute("SELECT id FROM users WHERE email = ?", ('aquaboxs34@hotmail.com',)).fetchone()[0]
    
    sample_contacts = [
        ('testuser@hotmail.com', 'Test User', 'FL'),
        ('friend1@hotmail.com', 'Friend One', 'FL'),
        ('buddy@msn.com', 'My Buddy', 'FL'),
        ('contact@example.com', 'Example Contact', 'AL')
    ]
    
    for contact_email, contact_name, list_type in sample_contacts:
        cursor.execute("""
            INSERT INTO contacts (user_id, contact_email, contact_name, list_type)
            VALUES (?, ?, ?, ?)
        """, (main_user_id, contact_email, contact_name, list_type))
        print(f"✅ Added contact: {contact_email}")
    
    conn.commit()
    conn.close()
    
    print("\n🟢 Database setup completed successfully!")
    print("📊 Ready for MSN Messenger connections")

def add_user(email, password, display_name=None):
    """Add a new user to the database"""
    conn = sqlite3.connect('database/msn_messenger.db')
    cursor = conn.cursor()
    
    if not display_name:
        display_name = email.split('@')[0]
    
    try:
        cursor.execute("""
            INSERT INTO users (email, password, display_name)
            VALUES (?, ?, ?)
        """, (email, password, display_name))
        conn.commit()
        print(f"✅ User added: {email}")
    except sqlite3.IntegrityError:
        print(f"❌ User already exists: {email}")
    
    conn.close()

def list_users():
    """List all users in the database"""
    conn = sqlite3.connect('database/msn_messenger.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT email, display_name, status FROM users")
    users = cursor.fetchall()
    
    print("\n📋 Current Users:")
    print("-" * 50)
    for email, display_name, status in users:
        print(f"Email: {email}")
        print(f"Display Name: {display_name}")
        print(f"Status: {status}")
        print("-" * 30)
    
    conn.close()

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "setup":
            setup_database()
        elif command == "add" and len(sys.argv) >= 4:
            email = sys.argv[2]
            password = sys.argv[3]
            display_name = sys.argv[4] if len(sys.argv) > 4 else None
            add_user(email, password, display_name)
        elif command == "list":
            list_users()
        else:
            print("Usage:")
            print("  python database_setup.py setup")
            print("  python database_setup.py add <email> <password> [display_name]")
            print("  python database_setup.py list")
    else:
        setup_database()
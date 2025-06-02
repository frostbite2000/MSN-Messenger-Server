#!/usr/bin/env python3
"""
MSN Messenger Server with MSNP Protocol Implementation
Based on spz2020/MED-6-7 with comprehensive protocol support
Supports MSNP protocol detection in Wireshark
"""

import socket
import threading
import sqlite3
import logging
import time
import hashlib
import xml.etree.ElementTree as ET
from flask import Flask, render_template, request
from datetime import datetime
import re
import struct

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('msn_server.log'),
        logging.StreamHandler()
    ]
)

class MSNPServer:
    def __init__(self, host='0.0.0.0', port=1863):
        self.host = host
        self.port = port
        self.clients = {}
        self.client_counter = 1
        self.running = False
        
        # MSNP Protocol versions supported
        self.supported_versions = ["MSNP2", "MSNP3", "MSNP4", "MSNP5", "MSNP6", "MSNP7"]
        self.challenge_key = "Q1P7W2E4J9R8U3S5"
        
        # Initialize database
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database for users and contacts"""
        try:
            conn = sqlite3.connect('database/msn_messenger.db')
            
            # Users table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    display_name TEXT,
                    status TEXT DEFAULT 'NLN',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Contacts table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS contacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    contact_email TEXT,
                    contact_name TEXT,
                    list_type TEXT DEFAULT 'FL',
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Messages table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_user TEXT,
                    to_user TEXT,
                    message TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Add default users for testing
            conn.execute("INSERT OR IGNORE INTO users (email, password, display_name) VALUES (?, ?, ?)", 
                        ('aquaboxs34@hotmail.com', 'password123', 'AquaBoxs'))
            conn.execute("INSERT OR IGNORE INTO users (email, password, display_name) VALUES (?, ?, ?)", 
                        ('testuser@hotmail.com', 'test123', 'Test User'))
            
            conn.commit()
            conn.close()
            logging.info("Database initialized successfully")
            
        except Exception as e:
            logging.error(f"Database initialization error: {e}")

    def start_server(self):
        """Start the MSNP server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(50)
            self.running = True
            
            logging.info(f"MSN Messenger Server started on {self.host}:{self.port}")
            print(f"🟢 MSN Messenger Server running on {self.host}:{self.port}")
            print("📊 Monitor with Wireshark - Filter: tcp.port == 1863 or msnms")
            
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    client_id = self.client_counter
                    self.client_counter += 1
                    
                    logging.info(f"New client connection from {address} - ID: {client_id}")
                    
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address, client_id)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.error as e:
                    if self.running:
                        logging.error(f"Socket error: {e}")
                        
        except Exception as e:
            logging.error(f"Server startup error: {e}")
        finally:
            self.server_socket.close()

    def handle_client(self, client_socket, address, client_id):
        """Handle individual client connection with MSNP protocol"""
        client_info = {
            'socket': client_socket,
            'address': address,
            'id': client_id,
            'authenticated': False,
            'email': None,
            'transaction_id': 0,
            'version': None,
            'status': 'FLN'
        }
        
        self.clients[client_id] = client_info
        
        try:
            while self.running:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                message = data.decode('utf-8', errors='ignore').strip()
                logging.debug(f"Client {client_id} -> Server: {message}")
                
                # Process MSNP commands
                self.process_msnp_command(client_info, message)
                
        except ConnectionResetError:
            logging.info(f"Client {client_id} disconnected")
        except Exception as e:
            logging.error(f"Client {client_id} error: {e}")
        finally:
            self.cleanup_client(client_id)

    def process_msnp_command(self, client_info, message):
        """Process MSNP protocol commands"""
        if not message:
            return
            
        parts = message.split()
        if len(parts) < 1:
            return
            
        command = parts[0].upper()
        client_socket = client_info['socket']
        
        try:
            if command == "VER":
                self.handle_ver_command(client_info, parts)
            elif command == "CVR":
                self.handle_cvr_command(client_info, parts)
            elif command == "USR":
                self.handle_usr_command(client_info, parts)
            elif command == "SYN":
                self.handle_syn_command(client_info, parts)
            elif command == "CHG":
                self.handle_chg_command(client_info, parts)
            elif command == "LST":
                self.handle_lst_command(client_info, parts)
            elif command == "ADD":
                self.handle_add_command(client_info, parts)
            elif command == "REM":
                self.handle_rem_command(client_info, parts)
            elif command == "MSG":
                self.handle_msg_command(client_info, parts, message)
            elif command == "OUT":
                self.handle_out_command(client_info, parts)
            elif command == "PNG":
                self.handle_png_command(client_info, parts)
            elif command == "QNG":
                self.handle_qng_command(client_info, parts)
            else:
                logging.warning(f"Unknown command from client {client_info['id']}: {command}")
                
        except Exception as e:
            logging.error(f"Command processing error: {e}")
            self.send_error(client_info, "911")

    def handle_ver_command(self, client_info, parts):
        """Handle VER (Version) command - Protocol negotiation"""
        if len(parts) < 3:
            self.send_error(client_info, "501")
            return
            
        transaction_id = parts[1]
        client_versions = parts[2:]
        
        # Find highest supported version
        supported_version = None
        for version in reversed(self.supported_versions):
            if version in client_versions:
                supported_version = version
                break
                
        if not supported_version:
            supported_version = "MSNP7"  # Default fallback
            
        client_info['version'] = supported_version
        
        response = f"VER {transaction_id} {supported_version}\r\n"
        self.send_response(client_info, response)

    def handle_cvr_command(self, client_info, parts):
        """Handle CVR (Client Version) command"""
        if len(parts) < 8:
            self.send_error(client_info, "501")
            return
            
        transaction_id = parts[1]
        
        # Respond with server version info
        response = f"CVR {transaction_id} 7.0.0816 7.0.0816 7.0.0816 http://messenger.msn.com http://messenger.msn.com\r\n"
        self.send_response(client_info, response)

    def handle_usr_command(self, client_info, parts):
        """Handle USR (User Authentication) command"""
        if len(parts) < 4:
            self.send_error(client_info, "501")
            return
            
        transaction_id = parts[1]
        auth_type = parts[2]
        
        if auth_type == "MD5" and len(parts) == 4:
            # Initial authentication request
            username = parts[3]
            challenge = self.generate_challenge()
            
            response = f"USR {transaction_id} MD5 S {challenge}\r\n"
            client_info['challenge'] = challenge
            client_info['username'] = username
            self.send_response(client_info, response)
            
        elif auth_type == "MD5" and len(parts) == 5:
            # Authentication response with hash
            username = parts[3]
            client_hash = parts[4]
            
            if self.authenticate_user(username, client_hash, client_info.get('challenge', '')):
                client_info['authenticated'] = True
                client_info['email'] = username
                client_info['status'] = 'NLN'
                
                display_name = self.get_display_name(username)
                response = f"USR {transaction_id} OK {username} {display_name}\r\n"
                self.send_response(client_info, response)
                
                # Send initial presence notification
                self.send_initial_presence(client_info)
            else:
                response = f"USR {transaction_id} 911 0\r\n"
                self.send_response(client_info, response)

    def handle_syn_command(self, client_info, parts):
        """Handle SYN (Synchronize) command - Contact list sync"""
        if not client_info['authenticated']:
            self.send_error(client_info, "911")
            return
            
        transaction_id = parts[1] if len(parts) > 1 else "0"
        
        # Get contact list from database
        contacts = self.get_user_contacts(client_info['email'])
        
        # Send synchronization response
        response = f"SYN {transaction_id} {len(contacts)} 0\r\n"
        self.send_response(client_info, response)
        
        # Send contact list
        for contact in contacts:
            lst_response = f"LST {contact['email']} {contact['name']} {contact['list_type']}\r\n"
            self.send_response(client_info, lst_response)

    def handle_chg_command(self, client_info, parts):
        """Handle CHG (Change Status) command"""
        if not client_info['authenticated']:
            self.send_error(client_info, "911")
            return
            
        if len(parts) < 3:
            self.send_error(client_info, "501")
            return
            
        transaction_id = parts[1]
        new_status = parts[2]
        
        client_info['status'] = new_status
        
        response = f"CHG {transaction_id} {new_status}\r\n"
        self.send_response(client_info, response)
        
        # Notify other clients about status change
        self.broadcast_status_change(client_info)

    def handle_msg_command(self, client_info, parts, full_message):
        """Handle MSG (Message) command"""
        if not client_info['authenticated']:
            self.send_error(client_info, "911")
            return
            
        if len(parts) < 4:
            self.send_error(client_info, "501")
            return
            
        transaction_id = parts[1]
        recipient = parts[2] if parts[2] != "U" else None
        msg_length = int(parts[3])
        
        # Extract message body
        header_end = full_message.find('\r\n')
        if header_end != -1:
            message_body = full_message[header_end + 2:header_end + 2 + msg_length]
            
            # Store message in database
            self.store_message(client_info['email'], recipient, message_body)
            
            # Send ACK
            response = f"ACK {transaction_id}\r\n"
            self.send_response(client_info, response)
            
            # Forward message to recipient if online
            if recipient:
                self.forward_message(client_info['email'], recipient, message_body)

    def handle_lst_command(self, client_info, parts):
        """Handle LST (List) command - Contact list request"""
        # This is typically sent by server to client, not handled here
        pass

    def handle_add_command(self, client_info, parts):
        """Handle ADD (Add Contact) command"""
        if not client_info['authenticated']:
            self.send_error(client_info, "911")
            return
            
        if len(parts) < 5:
            self.send_error(client_info, "501")
            return
            
        transaction_id = parts[1]
        list_type = parts[2]
        contact_email = parts[3]
        contact_name = parts[4]
        
        # Add contact to database
        self.add_contact(client_info['email'], contact_email, contact_name, list_type)
        
        response = f"ADD {transaction_id} {list_type} {contact_email} {contact_name}\r\n"
        self.send_response(client_info, response)

    def handle_rem_command(self, client_info, parts):
        """Handle REM (Remove Contact) command"""
        if not client_info['authenticated']:
            self.send_error(client_info, "911")
            return
            
        if len(parts) < 4:
            self.send_error(client_info, "501")
            return
            
        transaction_id = parts[1]
        list_type = parts[2]
        contact_email = parts[3]
        
        # Remove contact from database
        self.remove_contact(client_info['email'], contact_email, list_type)
        
        response = f"REM {transaction_id} {list_type} {contact_email}\r\n"
        self.send_response(client_info, response)

    def handle_out_command(self, client_info, parts):
        """Handle OUT (Logout) command"""
        response = "OUT\r\n"
        self.send_response(client_info, response)
        client_info['socket'].close()

    def handle_png_command(self, client_info, parts):
        """Handle PNG (Ping) command"""
        response = "QNG 50\r\n"
        self.send_response(client_info, response)

    def handle_qng_command(self, client_info, parts):
        """Handle QNG (Ping Response) command"""
        # Client ping response, no action needed
        pass

    def generate_challenge(self):
        """Generate authentication challenge"""
        import random
        import string
        return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

    def authenticate_user(self, username, client_hash, challenge):
        """Authenticate user with MD5 challenge"""
        try:
            conn = sqlite3.connect('database/msn_messenger.db')
            cursor = conn.cursor()
            
            cursor.execute("SELECT password FROM users WHERE email = ?", (username,))
            result = cursor.fetchone()
            conn.close()
            
            if result:
                password = result[0]
                # Create expected hash: MD5(MD5(password) + challenge)
                password_hash = hashlib.md5(password.encode()).hexdigest()
                expected_hash = hashlib.md5((password_hash + challenge).encode()).hexdigest()
                
                return client_hash.lower() == expected_hash.lower()
            
            return False
            
        except Exception as e:
            logging.error(f"Authentication error: {e}")
            return False

    def get_display_name(self, email):
        """Get user's display name"""
        try:
            conn = sqlite3.connect('database/msn_messenger.db')
            cursor = conn.cursor()
            
            cursor.execute("SELECT display_name FROM users WHERE email = ?", (email,))
            result = cursor.fetchone()
            conn.close()
            
            return result[0] if result and result[0] else email.split('@')[0]
            
        except Exception as e:
            logging.error(f"Display name error: {e}")
            return email.split('@')[0]

    def get_user_contacts(self, email):
        """Get user's contact list"""
        try:
            conn = sqlite3.connect('database/msn_messenger.db')
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT contact_email, contact_name, list_type 
                FROM contacts c
                JOIN users u ON c.user_id = u.id
                WHERE u.email = ?
            """, (email,))
            
            results = cursor.fetchall()
            conn.close()
            
            contacts = []
            for row in results:
                contacts.append({
                    'email': row[0],
                    'name': row[1] or row[0].split('@')[0],
                    'list_type': row[2]
                })
            
            return contacts
            
        except Exception as e:
            logging.error(f"Contact list error: {e}")
            return []

    def store_message(self, from_user, to_user, message):
        """Store message in database"""
        try:
            conn = sqlite3.connect('database/msn_messenger.db')
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO messages (from_user, to_user, message)
                VALUES (?, ?, ?)
            """, (from_user, to_user, message))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logging.error(f"Message storage error: {e}")

    def add_contact(self, user_email, contact_email, contact_name, list_type):
        """Add contact to user's list"""
        try:
            conn = sqlite3.connect('database/msn_messenger.db')
            cursor = conn.cursor()
            
            # Get user ID
            cursor.execute("SELECT id FROM users WHERE email = ?", (user_email,))
            user_result = cursor.fetchone()
            
            if user_result:
                user_id = user_result[0]
                cursor.execute("""
                    INSERT OR REPLACE INTO contacts (user_id, contact_email, contact_name, list_type)
                    VALUES (?, ?, ?, ?)
                """, (user_id, contact_email, contact_name, list_type))
                
                conn.commit()
            
            conn.close()
            
        except Exception as e:
            logging.error(f"Add contact error: {e}")

    def remove_contact(self, user_email, contact_email, list_type):
        """Remove contact from user's list"""
        try:
            conn = sqlite3.connect('database/msn_messenger.db')
            cursor = conn.cursor()
            
            cursor.execute("""
                DELETE FROM contacts 
                WHERE user_id = (SELECT id FROM users WHERE email = ?)
                AND contact_email = ? AND list_type = ?
            """, (user_email, contact_email, list_type))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logging.error(f"Remove contact error: {e}")

    def send_response(self, client_info, response):
        """Send response to client"""
        try:
            client_info['socket'].send(response.encode('utf-8'))
            logging.debug(f"Server -> Client {client_info['id']}: {response.strip()}")
        except Exception as e:
            logging.error(f"Send response error: {e}")

    def send_error(self, client_info, error_code):
        """Send error response to client"""
        response = f"{error_code}\r\n"
        self.send_response(client_info, response)

    def send_initial_presence(self, client_info):
        """Send initial presence notifications"""
        # Send user's own status
        response = f"NLN {client_info['status']} {client_info['email']} {self.get_display_name(client_info['email'])}\r\n"
        self.send_response(client_info, response)

    def broadcast_status_change(self, client_info):
        """Broadcast status change to other clients"""
        status_message = f"NLN {client_info['status']} {client_info['email']} {self.get_display_name(client_info['email'])}\r\n"
        
        for other_client_id, other_client in self.clients.items():
            if (other_client_id != client_info['id'] and 
                other_client['authenticated'] and 
                other_client['socket']):
                try:
                    other_client['socket'].send(status_message.encode('utf-8'))
                except:
                    pass

    def forward_message(self, from_user, to_user, message):
        """Forward message to recipient if online"""
        for client_id, client in self.clients.items():
            if (client['authenticated'] and 
                client['email'] == to_user and 
                client['socket']):
                try:
                    msg_response = f"MSG {from_user} {self.get_display_name(from_user)} {len(message)}\r\n{message}"
                    client['socket'].send(msg_response.encode('utf-8'))
                except:
                    pass

    def cleanup_client(self, client_id):
        """Clean up client connection"""
        if client_id in self.clients:
            client_info = self.clients[client_id]
            try:
                client_info['socket'].close()
            except:
                pass
            del self.clients[client_id]
            logging.info(f"Client {client_id} cleaned up")

    def stop_server(self):
        """Stop the server"""
        self.running = False
        if hasattr(self, 'server_socket'):
            self.server_socket.close()


class MSNWebServer:
    """HTTP server for MSN authentication and web services"""
    
    def __init__(self, host='0.0.0.0', port=80):
        self.app = Flask(__name__)
        self.host = host
        self.port = port
        self.setup_routes()

    def setup_routes(self):
        """Setup Flask routes for MSN web services"""
        
        @self.app.route("/login.live.com/ppsecure/clientpost.srf", methods=['POST'])
        def clientpost():
            host = self.get_host()
            content_type = request.headers.get("Content-Type")
            
            if content_type == "text/xml":
                xml_data = request.data
                try:
                    root = ET.fromstring(xml_data)
                    sign_in_name = root.find('.//SignInName').text
                    password = root.find('.//Password').text
                    
                    if self.authenticate_web_user(sign_in_name, password):
                        return self.render_success_response(host)
                    else:
                        return '<?xml version="1.0" encoding="utf-8"?><LoginResponse Success="false"></LoginResponse>'
                        
                except ET.ParseError as e:
                    return str(e), 400
                    
            return "Invalid request", 400

        @self.app.route("/login.live.com/ppsecure/ClientProfileRequest.srf", methods=['POST'])
        def client_profile_request():
            content_type = request.headers.get("Content-Type")
            
            if content_type == "text/xml":
                xml_data = request.data
                try:
                    root = ET.fromstring(xml_data)
                    sign_in_name = root.find('.//SignInName').text
                    password = root.find('.//Password').text
                    
                    if self.authenticate_web_user(sign_in_name, password):
                        return self.render_profile_response(sign_in_name, password)
                    else:
                        return '<?xml version="1.0" encoding="utf-8"?><ProfileResponse Success="false"></ProfileResponse>'
                        
                except ET.ParseError as e:
                    return str(e), 400
                    
            return "Invalid request", 400

        @self.app.route("/nexus.passport.com/client/client.xml")
        def client_xml():
            host = self.get_host()
            return self.render_client_xml(host)

        @self.app.route("/login.live.com/logoutxml.srf")
        def logout_xml():
            return '<?xml version="1.0" encoding="utf-8"?><LogoutResponse Success="true"></LogoutResponse>'

        @self.app.route("/")
        def index():
            return """
            <html>
            <head><title>MSN Messenger Server</title></head>
            <body>
                <h1>🟢 MSN Messenger Server Active</h1>
                <p>MSNP Server: Port 1863</p>
                <p>Web Services: Port 80</p>
                <p>Monitor with Wireshark: tcp.port == 1863 or msnms</p>
            </body>
            </html>
            """

    def authenticate_web_user(self, email, password):
        """Authenticate user for web services"""
        try:
            conn = sqlite3.connect('database/msn_messenger.db')
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, password))
            result = cursor.fetchone()
            conn.close()
            
            return result is not None
            
        except Exception as e:
            logging.error(f"Web authentication error: {e}")
            return False

    def render_success_response(self, host):
        """Render successful login response"""
        return f'''<?xml version="1.0" encoding="utf-8"?>
<LoginResponse Success="true">
    <Server>{host}</Server>
    <Timestamp>{int(time.time())}</Timestamp>
</LoginResponse>'''

    def render_profile_response(self, email, password):
        """Render profile response"""
        return f'''<?xml version="1.0" encoding="utf-8"?>
<ProfileResponse Success="true">
    <Email>{email}</Email>
    <DisplayName>{email.split('@')[0]}</DisplayName>
</ProfileResponse>'''

    def render_client_xml(self, host):
        """Render client configuration XML"""
        return f'''<?xml version="1.0" encoding="utf-8"?>
<ClientConfig>
    <Server>{host}</Server>
    <Port>1863</Port>
    <SSL>false</SSL>
</ClientConfig>'''

    def get_host(self):
        """Get request host"""
        return request.headers.get('host', 'localhost')

    def run(self):
        """Run the web server"""
        logging.info(f"MSN Web Server starting on {self.host}:{self.port}")
        self.app.run(host=self.host, port=self.port, debug=False, threaded=True)


def create_database_directory():
    """Create database directory if it doesn't exist"""
    import os
    if not os.path.exists('database'):
        os.makedirs('database')
        logging.info("Created database directory")


def main():
    """Main server startup"""
    print("🚀 Starting MSN Messenger Server with MSNP Protocol Support")
    print("=" * 60)
    
    # Create database directory
    create_database_directory()
    
    # Start MSNP server
    msnp_server = MSNPServer(host='0.0.0.0', port=1863)
    msnp_thread = threading.Thread(target=msnp_server.start_server)
    msnp_thread.daemon = True
    msnp_thread.start()
    
    # Start web server
    web_server = MSNWebServer(host='0.0.0.0', port=8080)  # Changed to 8080 to avoid conflicts
    web_thread = threading.Thread(target=web_server.run)
    web_thread.daemon = True
    web_thread.start()
    
    print("\n🟢 MSN Messenger Server is running!")
    print("📊 MSNP Protocol Server: localhost:1863")
    print("🌐 Web Services: localhost:8080")
    print("📋 Wireshark Filter: tcp.port == 1863 or msnms")
    print("📝 Log file: msn_server.log")
    print("\nPress Ctrl+C to stop the server")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down MSN Messenger Server...")
        msnp_server.stop_server()
        logging.info("MSN Messenger Server stopped")


if __name__ == "__main__":
    main()
import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class ClientManager:
    def __init__(self):
        self.clients = {}  # client_id -> client_info
        self.email_to_client = {}  # email -> client_id
        self.next_client_id = 1
    
    async def add_client(self, writer, email: str) -> int:
        """Add a new client connection"""
        client_id = self.next_client_id
        self.next_client_id += 1
        
        client_info = {
            'id': client_id,
            'email': email,
            'writer': writer,
            'status': 'NLN',  # Online
            'connected_at': datetime.now(),
            'last_activity': datetime.now()
        }
        
        self.clients[client_id] = client_info
        self.email_to_client[email] = client_id
        
        logger.info(f'Client added: {email} (ID: {client_id})')
        return client_id
    
    async def disconnect_client(self, writer):
        """Disconnect a client"""
        client_to_remove = None
        
        for client_id, client_info in self.clients.items():
            if client_info['writer'] == writer:
                client_to_remove = client_id
                break
        
        if client_to_remove:
            client_info = self.clients[client_to_remove]
            email = client_info['email']
            
            del self.clients[client_to_remove]
            if email in self.email_to_client:
                del self.email_to_client[email]
            
            logger.info(f'Client disconnected: {email} (ID: {client_to_remove})')
    
    async def get_client_by_email(self, email: str) -> Optional[dict]:
        """Get client info by email"""
        client_id = self.email_to_client.get(email)
        if client_id:
            return self.clients.get(client_id)
        return None
    
    async def get_client_by_id(self, client_id: int) -> Optional[dict]:
        """Get client info by ID"""
        return self.clients.get(client_id)
    
    async def update_client_status(self, client_id: int, status: str):
        """Update client status"""
        if client_id in self.clients:
            self.clients[client_id]['status'] = status
            self.clients[client_id]['last_activity'] = datetime.now()
            logger.info(f'Client {client_id} status updated to: {status}')
    
    async def get_online_contacts(self, email: str) -> List[dict]:
        """Get online contacts for a user"""
        # This would typically query the database for user's contacts
        # and check which ones are online
        online_contacts = []
        
        for client_info in self.clients.values():
            if client_info['email'] != email and client_info['status'] != 'HDN':  # Not hidden
                online_contacts.append({
                    'email': client_info['email'],
                    'status': client_info['status']
                })
        
        return online_contacts
    
    def get_all_clients(self) -> Dict[int, dict]:
        """Get all connected clients"""
        return self.clients.copy()
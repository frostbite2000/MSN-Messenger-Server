import asyncio
import logging
import hashlib
import uuid
from datetime import datetime

logger = logging.getLogger(__name__)

class MSNPProtocolHandler:
    def __init__(self, reader, writer, client_manager, message_router, db_manager):
        self.reader = reader
        self.writer = writer
        self.client_manager = client_manager
        self.message_router = message_router
        self.db_manager = db_manager
        self.client_id = None
        self.email = None
        self.transaction_id = 0
        self.authenticated = False
        self.protocol_version = None
        
    async def handle_connection(self):
        """Main connection handler"""
        while True:
            try:
                data = await self.reader.readline()
                if not data:
                    break
                    
                message = data.decode('utf-8').strip()
                if not message:
                    continue
                    
                logger.debug(f'Received: {message}')
                await self.process_command(message)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f'Error processing command: {e}')
                break
    
    async def process_command(self, message):
        """Process MSNP command"""
        parts = message.split(' ')
        if len(parts) < 2:
            return
            
        command = parts[0]
        transaction_id = parts[1] if len(parts) > 1 else '0'
        
        # Route command to appropriate handler
        command_handlers = {
            'VER': self.handle_ver,
            'CVR': self.handle_cvr,
            'USR': self.handle_usr,
            'SYN': self.handle_syn,
            'CHG': self.handle_chg,
            'MSG': self.handle_msg,
            'ADD': self.handle_add,
            'REM': self.handle_rem,
            'LST': self.handle_lst,
            'CAL': self.handle_cal,
            'ANS': self.handle_ans,
            'OUT': self.handle_out,
            'PNG': self.handle_png,
            'QNG': self.handle_qng
        }
        
        handler = command_handlers.get(command)
        if handler:
            await handler(parts, transaction_id)
        else:
            logger.warning(f'Unknown command: {command}')
    
    async def handle_ver(self, parts, transaction_id):
        """Handle VER (version) command"""
        # VER 1 MSNP21 MSNP20 MSNP19 MSNP18
        supported_versions = ['MSNP21', 'MSNP20', 'MSNP19', 'MSNP18', 'MSNP15', 'MSNP12', 'MSNP11', 'MSNP10', 'MSNP9', 'MSNP8']
        
        # Find highest supported version
        client_versions = parts[2:] if len(parts) > 2 else []
        selected_version = None
        
        for version in supported_versions:
            if version in client_versions:
                selected_version = version
                break
        
        if not selected_version:
            selected_version = 'MSNP8'  # Fallback to basic version
            
        self.protocol_version = selected_version
        response = f'VER {transaction_id} {selected_version}\r\n'
        await self.send_response(response)
    
    async def handle_cvr(self, parts, transaction_id):
        """Handle CVR (client version) command"""
        # CVR 2 0x0409 winnt 10.0 i386 MSNMSGR 8.5.1302 msmsgs user@hotmail.com
        response = f'CVR {transaction_id} 8.5.1302 8.5.1302 8.5.1302 http://messenger.msn.com\r\n'
        await self.send_response(response)
    
    async def handle_usr(self, parts, transaction_id):
        """Handle USR (authentication) command"""
        if len(parts) < 4:
            await self.send_error(transaction_id, 911)
            return
            
        auth_type = parts[2]
        
        if auth_type == 'I':
            # Initial authentication request
            # USR 3 I user@hotmail.com
            if len(parts) >= 4:
                self.email = parts[3]
                # Send challenge for MD5 authentication
                challenge = str(uuid.uuid4())
                response = f'USR {transaction_id} S {challenge}\r\n'
                await self.send_response(response)
        
        elif auth_type == 'S':
            # Challenge response
            # USR 4 S response_hash
            if len(parts) >= 4 and self.email:
                provided_hash = parts[3]
                
                # Authenticate user
                user = await self.db_manager.get_user_by_email(self.email)
                if user:
                    # For simplicity, accept any hash (in real implementation, verify MD5 challenge)
                    self.authenticated = True
                    self.client_id = await self.client_manager.add_client(self.writer, self.email)
                    
                    response = f'USR {transaction_id} OK {self.email} {self.email} 1 0\r\n'
                    await self.send_response(response)
                else:
                    await self.send_error(transaction_id, 911)  # Authentication failed
    
    async def handle_syn(self, parts, transaction_id):
        """Handle SYN (synchronization) command"""
        if not self.authenticated:
            await self.send_error(transaction_id, 911)
            return
            
        # SYN 5 0 0
        # Return contact list and groups
        contacts = await self.db_manager.get_user_contacts(self.email)
        
        # Send contact list
        for contact in contacts:
            lst_response = f'LST {contact["email"]} {contact["nickname"]} {contact["list_type"]}\r\n'
            await self.send_response(lst_response)
        
        # Send sync completion
        response = f'SYN {transaction_id} {len(contacts)} 0\r\n'
        await self.send_response(response)
    
    async def handle_chg(self, parts, transaction_id):
        """Handle CHG (change status) command"""
        if not self.authenticated:
            await self.send_error(transaction_id, 911)
            return
            
        if len(parts) >= 3:
            status = parts[2]
            await self.client_manager.update_client_status(self.client_id, status)
            
            # Notify contacts about status change
            await self.message_router.broadcast_status_change(self.email, status)
            
            response = f'CHG {transaction_id} {status} 0\r\n'
            await self.send_response(response)
    
    async def handle_msg(self, parts, transaction_id):
        """Handle MSG (message) command"""
        if not self.authenticated:
            await self.send_error(transaction_id, 911)
            return
            
        # MSG 6 U 52
        # MIME-Version: 1.0
        # Content-Type: text/plain; charset=UTF-8
        # 
        # Hello World
        
        if len(parts) >= 4:
            msg_type = parts[2]
            msg_length = int(parts[3])
            
            # Read message payload
            payload = await self.reader.read(msg_length)
            message_content = payload.decode('utf-8')
            
            # Extract actual message from MIME content
            lines = message_content.split('\r\n')
            message_text = ''
            in_body = False
            
            for line in lines:
                if in_body:
                    message_text += line + '\n'
                elif line == '':
                    in_body = True
            
            # Route message (for now, just acknowledge)
            response = f'MSG {transaction_id} OK\r\n'
            await self.send_response(response)
    
    async def handle_cal(self, parts, transaction_id):
        """Handle CAL (call/invite) command"""
        # CAL 7 user@hotmail.com
        if len(parts) >= 3:
            target_email = parts[2]
            session_id = str(uuid.uuid4())
            
            # For now, just acknowledge the call
            response = f'CAL {transaction_id} RINGING {session_id}\r\n'
            await self.send_response(response)
    
    async def handle_ans(self, parts, transaction_id):
        """Handle ANS (answer) command"""
        # Answer an incoming call
        response = f'ANS {transaction_id} OK\r\n'
        await self.send_response(response)
    
    async def handle_add(self, parts, transaction_id):
        """Handle ADD (add contact) command"""
        if len(parts) >= 5:
            list_type = parts[2]
            email = parts[3]
            nickname = parts[4]
            
            await self.db_manager.add_contact(self.email, email, nickname, list_type)
            response = f'ADD {transaction_id} {list_type} {email} {nickname}\r\n'
            await self.send_response(response)
    
    async def handle_rem(self, parts, transaction_id):
        """Handle REM (remove contact) command"""
        if len(parts) >= 4:
            list_type = parts[2]
            email = parts[3]
            
            await self.db_manager.remove_contact(self.email, email, list_type)
            response = f'REM {transaction_id} {list_type} {email}\r\n'
            await self.send_response(response)
    
    async def handle_lst(self, parts, transaction_id):
        """Handle LST (list contacts) command"""
        contacts = await self.db_manager.get_user_contacts(self.email)
        
        for contact in contacts:
            response = f'LST {contact["email"]} {contact["nickname"]} {contact["list_type"]}\r\n'
            await self.send_response(response)
    
    async def handle_out(self, parts, transaction_id):
        """Handle OUT (logout) command"""
        await self.client_manager.disconnect_client(self.writer)
        response = f'OUT\r\n'
        await self.send_response(response)
    
    async def handle_png(self, parts, transaction_id):
        """Handle PNG (ping) command"""
        # Respond with QNG (quiet)
        response = f'QNG 60\r\n'
        await self.send_response(response)
    
    async def handle_qng(self, parts, transaction_id):
        """Handle QNG (quiet ping response) command"""
        # Just acknowledge
        pass
    
    async def send_response(self, response):
        """Send response to client"""
        logger.debug(f'Sending: {response.strip()}')
        self.writer.write(response.encode('utf-8'))
        await self.writer.drain()
    
    async def send_error(self, transaction_id, error_code):
        """Send error response"""
        response = f'{error_code} {transaction_id}\r\n'
        await self.send_response(response)
import asyncio
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class MSNPTestClient:
    def __init__(self, host='localhost', port=1863):
        self.host = host
        self.port = port
        self.reader = None
        self.writer = None
        self.transaction_id = 1
    
    async def connect(self):
        """Connect to MSNP server"""
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        logger.info(f'Connected to {self.host}:{self.port}')
    
    async def disconnect(self):
        """Disconnect from server"""
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
    
    async def send_command(self, command):
        """Send command to server"""
        logger.info(f'Sending: {command}')
        self.writer.write(f'{command}\r\n'.encode('utf-8'))
        await self.writer.drain()
        self.transaction_id += 1
    
    async def read_response(self):
        """Read response from server"""
        data = await self.reader.readline()
        response = data.decode('utf-8').strip()
        logger.info(f'Received: {response}')
        return response
    
    async def authenticate(self, email, password):
        """Perform authentication flow"""
        # Version negotiation
        await self.send_command(f'VER {self.transaction_id} MSNP8')
        await self.read_response()
        
        # Client version
        await self.send_command(f'CVR {self.transaction_id} 0x0409 winnt 10.0 i386 MSNMSGR 8.5.1302 msmsgs {email}')
        await self.read_response()
        
        # Initial authentication
        await self.send_command(f'USR {self.transaction_id} I {email}')
        challenge_response = await self.read_response()
        
        # Send challenge response (simplified)
        await self.send_command(f'USR {self.transaction_id} S dummy_hash')
        auth_response = await self.read_response()
        
        return 'OK' in auth_response
    
    async def sync_contacts(self):
        """Synchronize contact list"""
        await self.send_command(f'SYN {self.transaction_id} 0 0')
        return await self.read_response()
    
    async def change_status(self, status='NLN'):
        """Change online status"""
        await self.send_command(f'CHG {self.transaction_id} {status} 0')
        return await self.read_response()

async def test_client():
    """Test the MSNP server with a test client"""
    client = MSNPTestClient()
    
    try:
        await client.connect()
        
        # Test authentication
        success = await client.authenticate('test@example.com', 'password')
        if success:
            logger.info('Authentication successful')
            
            # Test synchronization
            await client.sync_contacts()
            
            # Test status change
            await client.change_status('NLN')
            
            # Keep connection alive for a bit
            await asyncio.sleep(5)
        
    except Exception as e:
        logger.error(f'Test failed: {e}')
    finally:
        await client.disconnect()

if __name__ == '__main__':
    asyncio.run(test_client())
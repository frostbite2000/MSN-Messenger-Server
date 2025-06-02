import asyncio
import logging
import socket
from datetime import datetime
from .protocol_handler import MSNPProtocolHandler
from .client_manager import ClientManager
from .message_router import MessageRouter
from utils.database import DatabaseManager

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MSNPServer:
    def __init__(self, host='localhost', port=1863):
        self.host = host
        self.port = port
        self.server = None
        self.client_manager = ClientManager()
        self.message_router = MessageRouter(self.client_manager)
        self.db_manager = DatabaseManager()
        
    async def start_server(self):
        """Start the MSNP server"""
        self.server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )
        
        addr = self.server.sockets[0].getsockname()
        logger.info(f'MSNP Server serving on {addr[0]}:{addr[1]}')
        
        async with self.server:
            await self.server.serve_forever()
    
    async def handle_client(self, reader, writer):
        """Handle new client connection"""
        client_addr = writer.get_extra_info('peername')
        logger.info(f'New connection from {client_addr}')
        
        # Create protocol handler for this client
        protocol_handler = MSNPProtocolHandler(
            reader, writer, self.client_manager, 
            self.message_router, self.db_manager
        )
        
        try:
            await protocol_handler.handle_connection()
        except Exception as e:
            logger.error(f'Error handling client {client_addr}: {e}')
        finally:
            # Clean up client connection
            await self.client_manager.disconnect_client(writer)
            writer.close()
            await writer.wait_closed()
            logger.info(f'Connection closed for {client_addr}')

    async def stop_server(self):
        """Stop the server"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info('Server stopped')

if __name__ == '__main__':
    server = MSNPServer()
    try:
        asyncio.run(server.start_server())
    except KeyboardInterrupt:
        logger.info('Server shutting down...')
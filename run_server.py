#!/usr/bin/env python3
import asyncio
import logging
import os
import sys
from pathlib import Path

# Add server directory to path
sys.path.append(str(Path(__file__).parent))

from server.msnp_server import MSNPServer
from config.server_config import config

def setup_logging():
    """Setup logging configuration"""
    log_level = getattr(logging, config.get('logging.level', 'INFO').upper())
    log_file = config.get('logging.file')
    
    # Create logs directory if it doesn't exist
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_file) if log_file else logging.NullHandler()
        ]
    )

async def main():
    """Main server entry point"""
    setup_logging()
    logger = logging.getLogger(__name__)
    
    # Create necessary directories
    os.makedirs('database', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    
    # Initialize server
    host = config.get('server.host', 'localhost')
    port = config.get('server.port', 1863)
    
    server = MSNPServer(host, port)
    
    logger.info(f'Starting MSN Messenger Server on {host}:{port}')
    logger.info(f'Supported MSNP versions: {config.get("protocol.supported_versions")}')
    
    try:
        await server.start_server()
    except KeyboardInterrupt:
        logger.info('Shutting down server...')
        await server.stop_server()
    except Exception as e:
        logger.error(f'Server error: {e}')
        raise

if __name__ == '__main__':
    asyncio.run(main())
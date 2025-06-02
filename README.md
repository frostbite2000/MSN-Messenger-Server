# MSN Messenger Server (MSNP Protocol)

A Python implementation of an MSN Messenger server supporting the Microsoft Notification Protocol (MSNP) as observed in Wireshark captures.

## Features

- **MSNP Protocol Support**: Handles VER, CVR, USR, SYN, CHG, MSG, and other MSNP commands
- **Multi-client Support**: Supports multiple simultaneous client connections
- **User Authentication**: Integrates with SQLite user database
- **Contact Management**: Handle buddy lists and presence status
- **Real-time Messaging**: Route instant messages between connected users
- **Session Management**: Maintain user sessions and connection states

## Installation

1. Clone the repository and navigate to the project directory
2. Run the setup script:
   ```bash
   python setup.py
   ```

3. Start the server:
   ```bash
   python run_server.py
   ```

## Configuration

Edit `config/server_config.py` to customize:
- Server host and port (default: localhost:1863)
- Database path
- Logging settings
- Protocol versions
- Feature toggles

## Testing

Run the test client to verify server functionality:
```bash
python tests/test_client.py
```

## Protocol Support

Based on the Wireshark captures, the server supports:
- Version negotiation (VER command)
- Client capability exchange (CVR command)
- User authentication (USR command with MD5 challenge)
- Contact synchronization (SYN command)
- Status changes (CHG command)
- Instant messaging (MSG command)
- Contact management (ADD, REM, LST commands)
- Connection management (CAL, ANS, OUT commands)
- Keep-alive (PNG/QNG commands)

## Database Schema

The server uses SQLite with the following tables:
- `users`: User accounts and credentials
- `contacts`: Contact lists and relationships
- `sessions`: Active user sessions
- `message_history`: Message history (optional)

## Architecture

- `server/msnp_server.py`: Main server implementation
- `server/protocol_handler.py`: MSNP protocol command handlers
- `server/client_manager.py`: Client connection management
- `server/message_router.py`: Message routing between clients
- `utils/database.py`: Database operations
- `config/server_config.py`: Server configuration

## Usage with MSN Messenger Clients

1. Start the server on port 1863
2. Configure MSN Messenger clients to connect to your server IP
3. Use the sample accounts or create new ones in the database
4. Authenticate and start messaging

## Sample Accounts

The setup creates these test accounts:
- test@example.com / password
- alice@example.com / password  
- bob@example.com / password
- Jessie@brawlstars.com / password

## Wireshark Analysis

The implementation is based on MSNP traffic analysis showing:
- Authentication flows with challenge-response
- Presence notifications and status updates
- Message exchange patterns
- Contact list synchronization
- Connection management

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test with real MSN Messenger clients
5. Submit a pull request

## License

This project is for educational and research purposes.
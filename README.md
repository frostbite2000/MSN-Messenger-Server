# MSN Messenger Server with MSNP Protocol Support

A comprehensive Python implementation of an MSN Messenger server that supports the MSNP (MSN Messenger Protocol) and can be detected in Wireshark network analysis.

## Features

🟢 **MSNP Protocol Server** (Port 1863)
- Full MSNP command support (VER, CVR, USR, SYN, CHG, MSG, etc.)
- Multi-threaded client handling
- MD5 challenge authentication
- Contact list management
- Real-time messaging
- Presence status updates

🟢 **Web Services** (Port 8080)
- MSN authentication endpoints
- XML-based login services
- Client configuration delivery

🟢 **Database System**
- SQLite3 user management
- Contact list storage
- Message history
- User profiles

🟢 **Wireshark Detection**
- MSNP protocol identification
- Proper packet structure
- Network analysis support

## Based on spz2020/MED-6-7

This implementation integrates and extends the original MED-6-7 project with:
- Complete MSNP protocol implementation
- Enhanced authentication system
- Multi-client support
- Database improvements
- Wireshark compatibility

## Quick Start

### 1. Setup Database
```bash
python3 database_setup.py setup
```

### 2. Start Server
```bash
python3 msn_messenger_server.py
```

### 3. Monitor with Wireshark
Filter: `tcp.port == 1863 or msnms`

## Server Configuration

- **MSNP Server**: localhost:1863
- **Web Services**: localhost:8080
- **Database**: SQLite3 (database/msn_messenger.db)
- **Logs**: msn_server.log

## Sample Users

The database comes pre-populated with test users:

| Email | Password | Display Name |
|-------|----------|--------------|
| aquaboxs34@hotmail.com | password123 | AquaBoxs |
| testuser@hotmail.com | test123 | Test User |
| friend1@hotmail.com | friend123 | Friend One |

## MSNP Protocol Commands Supported

- **VER**: Protocol version negotiation
- **CVR**: Client version information
- **USR**: User authentication (MD5 challenge)
- **SYN**: Contact list synchronization
- **CHG**: Status change
- **LST**: Contact list entries
- **ADD**: Add contact
- **REM**: Remove contact
- **MSG**: Send message
- **PNG**: Ping
- **QNG**: Ping response
- **OUT**: Logout

## Wireshark Analysis

The server generates proper MSNP protocol traffic that can be analyzed in Wireshark:

1. **Connection Setup**: TCP handshake on port 1863
2. **Protocol Negotiation**: VER command exchange
3. **Authentication**: MD5 challenge/response
4. **Contact Sync**: LST command sequences
5. **Messaging**: MSG command with proper payload
6. **Status Updates**: CHG/NLN notifications

## Database Management

### Add New User
```bash
python3 database_setup.py add user@example.com password123 "Display Name"
```

### List All Users
```bash
python3 database_setup.py list
```

## Docker Support

```bash
# Build image
docker build -t msn-messenger-server .

# Run container
docker run -p 1863:1863 -p 8080:8080 msn-messenger-server
```

## Development Notes

- Designed for MSN Explorer 6/7 compatibility
- Supports multiple concurrent clients
- Comprehensive logging for debugging
- Database-backed user management
- Real-time message forwarding

## Network Protocol Details

The server implements the complete MSNP handshake sequence:

```
Client -> Server: VER 1 MSNP7 MSNP6 MSNP5
Server -> Client: VER 1 MSNP7
Client -> Server: CVR 2 0x0409 win 4.10 i386 MSNMSGR 6.0.0602 MSMSGS
Server -> Client: CVR 2 6.0.0602 6.0.0602 6.0.0602 http://...
Client -> Server: USR 3 MD5 I user@hotmail.com
Server -> Client: USR 3 MD5 S challenge_string
Client -> Server: USR 4 MD5 S user@hotmail.com response_hash
Server -> Client: USR 4 OK user@hotmail.com Display%20Name
```

## Security Notes

⚠️ **Development Use Only**
- This server is designed for development and testing
- Not suitable for production environments
- Implements basic security measures only
- Use in controlled network environments

## Contributing

This server integrates code and concepts from:
- spz2020/MED-6-7 (Original Python port)
- Sgeo/MSN-Explorer-Enabler (Original implementation)

## License

Development and educational use only. Not for production deployment.
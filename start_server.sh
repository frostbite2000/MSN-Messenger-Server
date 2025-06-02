#!/bin/bash
echo "🚀 Starting MSN Messenger Server Setup"
echo "======================================"

# Create database directory
mkdir -p database

# Setup database
echo "📊 Setting up database..."
python3 database_setup.py setup

# Start the server
echo "🟢 Starting MSN Messenger Server..."
python3 msn_messenger_server.py
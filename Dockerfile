FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create database directory
RUN mkdir -p database

# Setup database
RUN python database_setup.py setup

# Expose ports
EXPOSE 1863 8080

# Start the server
CMD ["python", "msn_messenger_server.py"]
import os
from typing import Dict, Any

class ServerConfig:
    def __init__(self):
        self.config = {
            'server': {
                'host': os.getenv('MSNP_HOST', 'localhost'),
                'port': int(os.getenv('MSNP_PORT', 1863)),
                'max_connections': int(os.getenv('MSNP_MAX_CONNECTIONS', 1000))
            },
            'database': {
                'path': os.getenv('DB_PATH', 'database/user_system.db')
            },
            'logging': {
                'level': os.getenv('LOG_LEVEL', 'INFO'),
                'file': os.getenv('LOG_FILE', 'logs/msnp_server.log')
            },
            'protocol': {
                'supported_versions': ['MSNP21', 'MSNP20', 'MSNP19', 'MSNP18', 'MSNP15', 'MSNP12', 'MSNP11', 'MSNP10', 'MSNP9', 'MSNP8'],
                'default_version': 'MSNP8',
                'ping_interval': 60,
                'session_timeout': 3600
            },
            'features': {
                'enable_message_history': True,
                'enable_file_transfer': False,
                'enable_voice_chat': False,
                'max_message_length': 1664
            }
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot notation key"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value by dot notation key"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value

# Global configuration instance
config = ServerConfig()
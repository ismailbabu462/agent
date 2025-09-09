#!/usr/bin/env python3
"""
Desktop Agent for Pentest Suite
WebSocket server that executes pentest tools locally on the user's machine.
"""

import asyncio
import websockets
import json
import subprocess
import logging
import sys
import os
import shutil
from typing import Dict, List, Any
import re
import time
from datetime import datetime, timezone
import hashlib
import secrets
from collections import defaultdict, deque

# SECURITY CONFIGURATION
SECURITY_CONFIG = {
    'max_message_size': 1024 * 1024,  # 1MB max message size
    'max_connections_per_ip': 5,      # Max connections per IP
    'rate_limit_window': 60,          # Rate limit window in seconds
    'rate_limit_requests': 10,        # Max requests per window
    'connection_timeout': 300,        # 5 minutes connection timeout
    'max_concurrent_tools': 3,        # Max concurrent tool executions
    'process_timeout': 300,           # 5 minutes process timeout
    'max_output_size': 10 * 1024 * 1024,  # 10MB max output size
    'enable_logging': True,
    'log_sensitive_data': False       # Don't log sensitive data
}

# Configure logging with security considerations
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Security: Don't log sensitive information
class SecurityFilter(logging.Filter):
    def filter(self, record):
        # Remove sensitive data from logs
        if hasattr(record, 'msg'):
            msg = str(record.msg).lower()
            
            # More specific patterns to avoid false positives
            sensitive_patterns = [
                'password=', 'token=', 'secret=', 'api_key=', 'auth_key=',
                'private_key', 'access_token', 'refresh_token', 'jwt_token',
                'session_key', 'encryption_key', 'master_key'
            ]
            
            # Check for sensitive patterns (more specific)
            for pattern in sensitive_patterns:
                if pattern in msg:
                    record.msg = '[REDACTED]'
                    break
                    
            # Check for specific sensitive data formats
            import re
            sensitive_regex = [
                r'[a-zA-Z0-9]{32,}',  # Long alphanumeric strings (potential keys)
                r'Bearer\s+[A-Za-z0-9\-_]+',  # Bearer tokens
                r'[A-Za-z0-9+/]{40,}={0,2}',  # Base64 encoded data
            ]
            
            for regex_pattern in sensitive_regex:
                if re.search(regex_pattern, str(record.msg)):
                    # Only redact if it looks like actual sensitive data
                    if any(indicator in msg for indicator in ['token', 'key', 'secret', 'password']):
                        record.msg = '[REDACTED]'
                        break
                        
        return True

logger.addFilter(SecurityFilter())

# Tier limits for tool usage delays (in seconds)
TIER_LIMITS = {
    'essential': {'tool_delay_seconds': 5},
    'professional': {'tool_delay_seconds': 3},
    'teams': {'tool_delay_seconds': 2},
    'enterprise': {'tool_delay_seconds': 1},
    'elite': {'tool_delay_seconds': 0}
}

# Tool installation commands (multiple methods for each tool)
TOOL_INSTALLATION = {
    'subfinder': [
        # Windows methods
        ['powershell', '-Command', 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'],
        ['cmd', '/c', 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'],
        ['go', 'install', '-v', 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'],
        # Linux/macOS methods
        ['go', 'install', 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'],
        ['go', 'install', 'github.com/projectdiscovery/subfinder@latest']
    ],
    'nmap': [
        # Windows methods
        ['choco', 'install', 'nmap', '-y'],
        ['winget', 'install', 'Nmap.Nmap'],
        ['scoop', 'install', 'nmap'],
        # Linux methods - SECURITY: Split shell commands
        ['apt', 'update'],
        ['apt', 'install', '-y', 'nmap'],
        ['yum', 'install', '-y', 'nmap'],
        ['dnf', 'install', '-y', 'nmap'],
        # macOS methods
        ['brew', 'install', 'nmap']
    ],
    'gobuster': [
        # Windows methods
        ['powershell', '-Command', 'go install github.com/OJ/gobuster/v3@latest'],
        ['cmd', '/c', 'go install github.com/OJ/gobuster/v3@latest'],
        ['go', 'install', 'github.com/OJ/gobuster/v3@latest'],
        # Linux/macOS methods
        ['go', 'install', 'github.com/OJ/gobuster@latest'],
        ['apt', 'install', '-y', 'gobuster']
    ],
    'ffuf': [
        # Windows methods
        ['powershell', '-Command', 'go install github.com/ffuf/ffuf@latest'],
        ['cmd', '/c', 'go install github.com/ffuf/ffuf@latest'],
        ['go', 'install', 'github.com/ffuf/ffuf@latest'],
        # Linux/macOS methods
        ['go', 'install', 'github.com/ffuf/ffuf@v1.5.0'],
        ['apt', 'install', '-y', 'ffuf']
    ],
    'nuclei': [
        # Windows methods
        ['powershell', '-Command', 'go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest'],
        ['cmd', '/c', 'go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest'],
        ['go', 'install', '-v', 'github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest'],
        # Linux/macOS methods
        ['go', 'install', 'github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest'],
        ['go', 'install', 'github.com/projectdiscovery/nuclei@latest']
    ],
    'amass': [
        # Windows methods
        ['powershell', '-Command', 'go install -v github.com/owasp-amass/amass/v3/...@latest'],
        ['cmd', '/c', 'go install -v github.com/owasp-amass/amass/v3/...@latest'],
        ['go', 'install', '-v', 'github.com/owasp-amass/amass/v3/...@latest'],
        # Linux/macOS methods
        ['go', 'install', 'github.com/owasp-amass/amass/v3/...@latest'],
        ['go', 'install', 'github.com/owasp-amass/amass@latest']
    ]
}

# Whitelist of allowed tools (security measure)
ALLOWED_TOOLS = {
    'subfinder': {
        'command': 'subfinder',
        'args': ['-d', '{target}', '-silent'],
        'description': 'Fast passive subdomain discovery tool'
    },
    'nmap': {
        'command': 'nmap',
        'args': ['-sS', '-sV', '-O', '-p', '21,22,23,25,53,80,110,143,443,993,995,3306,3389,5432,8080,8443', '{target}'],
        'description': 'Network discovery and port scanning'
    },
    'gobuster': {
        'command': 'gobuster',
        'args': ['dir', '-u', '{target}', '-w', '/usr/share/wordlists/common.txt'],
        'description': 'Directory and file brute-forcer'
    },
    'ffuf': {
        'command': 'ffuf',
        'args': ['-u', '{target}/FUZZ', '-w', '/usr/share/wordlists/common.txt'],
        'description': 'Fast web fuzzer'
    },
    'nuclei': {
        'command': 'nuclei',
        'args': ['-u', '{target}', '-silent'],
        'description': 'Fast vulnerability scanner'
    },
    'amass': {
        'command': 'amass',
        'args': ['enum', '-d', '{target}'],
        'description': 'In-depth attack surface mapping'
    }
}

class DesktopAgent:
    def __init__(self, host='localhost', port=13337):
        self.host = host
        self.port = port
        self.clients = set()
        self.user_last_tool_run = {}  # Track last tool run time per user
        
        # SECURITY: Rate limiting and connection management
        self.rate_limits = defaultdict(lambda: deque())  # IP -> request times
        self.connections_per_ip = defaultdict(int)       # IP -> connection count
        self.active_tools = defaultdict(int)             # user_id -> active tool count
        self.client_ips = {}                             # websocket -> IP address
        self.session_tokens = {}                         # websocket -> session token
        self.max_output_size = SECURITY_CONFIG['max_output_size']
        self.current_output_size = 0
        
    def get_client_ip(self, websocket) -> str:
        """Get client IP address from websocket"""
        try:
            # Get IP from websocket headers
            if hasattr(websocket, 'remote_address'):
                return websocket.remote_address[0]
            elif hasattr(websocket, 'request_headers'):
                # Try to get from X-Forwarded-For or X-Real-IP
                forwarded_for = websocket.request_headers.get('X-Forwarded-For')
                if forwarded_for:
                    return forwarded_for.split(',')[0].strip()
                real_ip = websocket.request_headers.get('X-Real-IP')
                if real_ip:
                    return real_ip
            return 'unknown'
        except:
            return 'unknown'
    
    def check_rate_limit(self, ip: str) -> bool:
        """Check if IP is within rate limits"""
        now = time.time()
        window_start = now - SECURITY_CONFIG['rate_limit_window']
        
        # Clean old requests
        while self.rate_limits[ip] and self.rate_limits[ip][0] < window_start:
            self.rate_limits[ip].popleft()
        
        # Check if under limit
        if len(self.rate_limits[ip]) >= SECURITY_CONFIG['rate_limit_requests']:
            return False
        
        # Add current request
        self.rate_limits[ip].append(now)
        return True
    
    def check_connection_limit(self, ip: str) -> bool:
        """Check if IP has too many connections"""
        return self.connections_per_ip[ip] < SECURITY_CONFIG['max_connections_per_ip']
    
    def check_concurrent_tools(self, user_id: str) -> bool:
        """Check if user has too many concurrent tools running"""
        return self.active_tools[user_id] < SECURITY_CONFIG['max_concurrent_tools']
    
    def generate_session_token(self) -> str:
        """Generate a secure session token"""
        return secrets.token_urlsafe(32)
    
    def validate_session_token(self, websocket, token: str) -> bool:
        """Validate session token"""
        return self.session_tokens.get(websocket) == token

    async def register_client(self, websocket):
        """Register a new client connection with security checks"""
        client_ip = self.get_client_ip(websocket)
        
        # SECURITY: Check connection limits
        if not self.check_connection_limit(client_ip):
            logger.warning(f"Connection limit exceeded for IP: {client_ip}")
            await websocket.close(code=1013, reason="Too many connections")
            return False
        
        # SECURITY: Check rate limits
        if not self.check_rate_limit(client_ip):
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            await websocket.close(code=1013, reason="Rate limit exceeded")
            return False
        
        # Register client
        self.clients.add(websocket)
        self.client_ips[websocket] = client_ip
        self.connections_per_ip[client_ip] += 1
        self.session_tokens[websocket] = self.generate_session_token()
        
        logger.info(f"Client connected from {client_ip}. Total clients: {len(self.clients)}")
        return True
        
    async def unregister_client(self, websocket):
        """Unregister a client connection and cleanup security data"""
        if websocket in self.clients:
            client_ip = self.client_ips.get(websocket, 'unknown')
            
            # SECURITY: Cleanup connection tracking
            self.clients.discard(websocket)
            if client_ip in self.connections_per_ip:
                self.connections_per_ip[client_ip] = max(0, self.connections_per_ip[client_ip] - 1)
            
            # Cleanup security data
            self.client_ips.pop(websocket, None)
            self.session_tokens.pop(websocket, None)
            
            logger.info(f"Client disconnected from {client_ip}. Total clients: {len(self.clients)}")
        
    async def send_to_client(self, websocket, message: Dict[str, Any]):
        """Send a message to a specific client with security checks"""
        try:
            # SECURITY: Check message size
            message_str = json.dumps(message)
            if len(message_str) > SECURITY_CONFIG['max_message_size']:
                logger.warning(f"Message too large: {len(message_str)} bytes")
                return
            
            # SECURITY: Check output size limits
            if 'line' in message:
                line_size = len(str(message['line']))
                if self.current_output_size + line_size > self.max_output_size:
                    logger.warning("Output size limit exceeded")
                    await websocket.send(json.dumps({
                        'type': 'error',
                        'message': 'Output size limit exceeded'
                    }))
                    return
                self.current_output_size += line_size
            
            await websocket.send(message_str)
        except websockets.exceptions.ConnectionClosed:
            await self.unregister_client(websocket)
        except Exception as e:
            logger.error(f"Error sending message: {str(e)}")
            await self.unregister_client(websocket)
            
    async def broadcast_to_clients(self, message: Dict[str, Any]):
        """Broadcast a message to all connected clients"""
        if self.clients:
            await asyncio.gather(
                *[self.send_to_client(client, message) for client in self.clients.copy()],
                return_exceptions=True
            )
            
    def validate_target(self, target: str) -> bool:
        """Validate target input for security - SECURITY ENHANCED"""
        # Basic validation
        if not target or len(target) > 255:
            return False
            
        # SECURITY: Check for dangerous characters and injection patterns
        dangerous_chars = [
            ';', '&', '|', '`', '$', '(', ')', '<', '>', '"', "'", 
            '\\', '/', '..', '\x00', '\n', '\r', '\t',  # Path traversal, null bytes, control chars
            '!', '@', '#', '%', '^', '*', '+', '=', '[', ']', '{', '}', 
            '~', '?', ':', ' ', '\x1b'  # Additional dangerous chars
        ]
        
        # Check for dangerous patterns
        dangerous_patterns = [
            r'\.\./',  # Path traversal
            r'\.\.\\',  # Windows path traversal
            r'%2e%2e',  # URL encoded path traversal
            r'%00',     # Null byte injection
            r'<script', # XSS attempts
            r'javascript:', # JavaScript injection
            r'data:',   # Data URI injection
            r'file:',   # File URI injection
        ]
        
        # Check for dangerous characters
        if any(char in target for char in dangerous_chars):
            return False
            
        # Check for dangerous patterns
        for pattern in dangerous_patterns:
            if re.search(pattern, target, re.IGNORECASE):
                return False
        
        # SECURITY: Strict validation patterns
        # Domain pattern (more restrictive)
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
        
        # IP pattern (IPv4 only, more restrictive)
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        
        # URL pattern (more restrictive)
        url_pattern = r'^https?://[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}(/.*)?$'
        
        # CIDR pattern for network ranges
        cidr_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-9]|[1-2][0-9]|3[0-2])$'
        
        return bool(
            re.match(domain_pattern, target) or 
            re.match(ip_pattern, target) or 
            re.match(url_pattern, target) or
            re.match(cidr_pattern, target)
        )
    
    def check_tool_delay(self, user_id: str, tier: str) -> bool:
        """Check if user can run a tool based on their tier delay"""
        if tier not in TIER_LIMITS:
            tier = 'essential'  # Default to essential if tier not found
            
        required_delay = TIER_LIMITS[tier]['tool_delay_seconds']
        
        if required_delay == 0:
            return True  # Elite tier has no delay
            
        now = datetime.now(timezone.utc)
        last_run = self.user_last_tool_run.get(user_id)
        
        if last_run:
            time_diff = (now - last_run).total_seconds()
            if time_diff < required_delay:
                return False
                
        # Update last run time
        self.user_last_tool_run[user_id] = now
        return True
    
    def get_remaining_delay(self, user_id: str, tier: str) -> float:
        """Get remaining delay time for user"""
        if tier not in TIER_LIMITS:
            tier = 'essential'
            
        required_delay = TIER_LIMITS[tier]['tool_delay_seconds']
        
        if required_delay == 0:
            return 0
            
        now = datetime.now(timezone.utc)
        last_run = self.user_last_tool_run.get(user_id)
        
        if last_run:
            time_diff = (now - last_run).total_seconds()
            remaining = required_delay - time_diff
            return max(0, remaining)
            
        return 0
    
    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available in PATH"""
        return shutil.which(tool_name) is not None
    
    async def install_tool(self, tool_name: str, websocket) -> bool:
        """Try to install a tool using multiple methods"""
        if tool_name not in TOOL_INSTALLATION:
            return False
            
        installation_commands = TOOL_INSTALLATION[tool_name]
        
        await self.send_to_client(websocket, {
            'type': 'output',
            'tool': tool_name,
            'line': f'🔧 Attempting to install {tool_name}...'
        })
        
        for i, command in enumerate(installation_commands, 1):
            try:
                await self.send_to_client(websocket, {
                    'type': 'output',
                    'tool': tool_name,
                    'line': f'📦 Method {i}: Trying {" ".join(command)}'
                })
                
                # SECURITY: Always use subprocess_exec to prevent shell injection
                # Handle different command types safely
                if '&&' in command:
                    # SECURITY: Split shell commands and execute separately
                    # This prevents shell injection attacks
                    shell_commands = []
                    current_cmd = []
                    for arg in command:
                        if arg == '&&':
                            if current_cmd:
                                shell_commands.append(current_cmd)
                                current_cmd = []
                        else:
                            current_cmd.append(arg)
                    if current_cmd:
                        shell_commands.append(current_cmd)
                    
                    # Execute each command separately
                    success = True
                    for cmd in shell_commands:
                        if cmd:  # Skip empty commands
                            process = await asyncio.create_subprocess_exec(
                                *cmd,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE
                            )
                            stdout, stderr = await process.communicate()
                            if process.returncode != 0:
                                success = False
                                break
                    
                    if success:
                        stdout = b"Commands executed successfully"
                        stderr = b""
                    else:
                        stdout = b""
                        stderr = b"Command sequence failed"
                        
                elif command[0] in ['powershell', 'cmd']:
                    # Windows shell commands - SECURITY: Use exec not shell
                    process = await asyncio.create_subprocess_exec(
                        *command,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, stderr = await process.communicate()
                else:
                    # Regular subprocess - SECURITY: Always use exec
                    process = await asyncio.create_subprocess_exec(
                        *command,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, stderr = await process.communicate()
                
                # Check if installation was successful
                if (not '&&' in command and process.returncode == 0) or ('&&' in command and success):
                    await self.send_to_client(websocket, {
                        'type': 'output',
                        'tool': tool_name,
                        'line': f'✅ {tool_name} installed successfully!'
                    })
                    
                    # Verify installation
                    if self.is_tool_available(tool_name):
                        return True
                    else:
                        await self.send_to_client(websocket, {
                            'type': 'output',
                            'tool': tool_name,
                            'line': f'⚠️ {tool_name} installed but not found in PATH'
                        })
                else:
                    error_msg = stderr.decode('utf-8', errors='ignore').strip()
                    await self.send_to_client(websocket, {
                        'type': 'output',
                        'tool': tool_name,
                        'line': f'❌ Method {i} failed: {error_msg}'
                    })
                    
            except Exception as e:
                await self.send_to_client(websocket, {
                    'type': 'output',
                    'tool': tool_name,
                    'line': f'❌ Method {i} error: {str(e)}'
                })
        
        await self.send_to_client(websocket, {
            'type': 'output',
            'tool': tool_name,
            'line': f'❌ Failed to install {tool_name} with all methods'
        })
        return False
    
    async def execute_tool(self, tool_name: str, target: str, websocket, user_id: str = None, tier: str = 'essential'):
        """Execute a pentest tool and stream output with enhanced security"""
        # SECURITY: Validate inputs
        if tool_name not in ALLOWED_TOOLS:
            await self.send_to_client(websocket, {
                'type': 'error',
                'message': f'Tool "{tool_name}" is not allowed'
            })
            return
            
        if not self.validate_target(target):
            await self.send_to_client(websocket, {
                'type': 'error',
                'message': 'Invalid target format'
            })
            return
        
        # SECURITY: Check concurrent tool limits
        if user_id and not self.check_concurrent_tools(user_id):
            await self.send_to_client(websocket, {
                'type': 'error',
                'message': f'Too many concurrent tools running. Max: {SECURITY_CONFIG["max_concurrent_tools"]}'
            })
            return
            
        # Check tool delay for user
        if user_id and not self.check_tool_delay(user_id, tier):
            remaining = self.get_remaining_delay(user_id, tier)
            await self.send_to_client(websocket, {
                'type': 'error',
                'message': f'Araçları kullanmak için {remaining:.1f} saniye daha beklemelisiniz. (Tier: {tier.upper()})'
            })
            return
        
        # SECURITY: Increment active tool counter
        if user_id:
            self.active_tools[user_id] += 1
        
        # Check if tool is available, if not try to install it
        if not self.is_tool_available(tool_name):
            await self.send_to_client(websocket, {
                'type': 'output',
                'tool': tool_name,
                'line': f'⚠️ {tool_name} not found. Attempting to install...'
            })
            
            installation_success = await self.install_tool(tool_name, websocket)
            if not installation_success:
                await self.send_to_client(websocket, {
                    'type': 'error',
                    'message': f'Tool "{tool_name}" not found and could not be installed. Please install it manually.'
                })
                return
            
        tool_config = ALLOWED_TOOLS[tool_name]
        
        # Prepare command
        command = [tool_config['command']]
        args = [arg.format(target=target) for arg in tool_config['args']]
        command.extend(args)
        
        logger.info(f"Executing: {' '.join(command)}")
        
        # Send start message
        await self.send_to_client(websocket, {
            'type': 'start',
            'tool': tool_name,
            'target': target,
            'command': ' '.join(command)
        })
        
        try:
            # SECURITY: Execute command with timeout and resource limits
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                # SECURITY: Set process limits
                preexec_fn=None if os.name == 'nt' else os.setsid  # Process group isolation
            )
            
            # SECURITY: Stream output with timeout protection
            timeout_seconds = SECURITY_CONFIG['process_timeout']
            start_time = time.time()
            
            while True:
                # SECURITY: Check for timeout
                if time.time() - start_time > timeout_seconds:
                    logger.warning(f"Process timeout for {tool_name}")
                    process.terminate()
                    await self.send_to_client(websocket, {
                        'type': 'error',
                        'message': f'Process timeout after {timeout_seconds} seconds'
                    })
                    break
                
                try:
                    # SECURITY: Read with timeout
                    line = await asyncio.wait_for(
                        process.stdout.readline(), 
                        timeout=1.0
                    )
                    if not line:
                        break
                        
                    # Decode bytes to string
                    decoded_line = line.decode('utf-8', errors='ignore').strip()
                    if decoded_line:
                        # Send output line
                        await self.send_to_client(websocket, {
                            'type': 'output',
                            'tool': tool_name,
                            'line': decoded_line
                        })
                except asyncio.TimeoutError:
                    # Continue if no output for 1 second
                    continue
                
            # Wait for process to complete
            try:
                return_code = await asyncio.wait_for(
                    process.wait(), 
                    timeout=5.0
                )
            except asyncio.TimeoutError:
                logger.warning(f"Process did not terminate gracefully for {tool_name}")
                process.kill()
                return_code = -1
            
            # Send completion message
            await self.send_to_client(websocket, {
                'type': 'complete',
                'tool': tool_name,
                'target': target,
                'return_code': return_code,
                'success': return_code == 0
            })
            
        except FileNotFoundError:
            await self.send_to_client(websocket, {
                'type': 'error',
                'message': f'Tool "{tool_name}" not found. Please install it first.'
            })
        except Exception as e:
            logger.error(f"Error executing {tool_name}: {str(e)}")
            await self.send_to_client(websocket, {
                'type': 'error',
                'message': f'Execution error: {str(e)}'
            })
        finally:
            # SECURITY: Decrement active tool counter
            if user_id:
                self.active_tools[user_id] = max(0, self.active_tools[user_id] - 1)
    
    async def handle_message(self, websocket, message: str):
        """Handle incoming WebSocket messages with security checks"""
        try:
            # SECURITY: Check message size
            if len(message) > SECURITY_CONFIG['max_message_size']:
                logger.warning(f"Message too large: {len(message)} bytes")
                await self.send_to_client(websocket, {
                    'type': 'error',
                    'message': 'Message too large'
                })
                return
            
            # SECURITY: Rate limiting check
            client_ip = self.client_ips.get(websocket, 'unknown')
            if not self.check_rate_limit(client_ip):
                logger.warning(f"Rate limit exceeded for {client_ip}")
                await self.send_to_client(websocket, {
                    'type': 'error',
                    'message': 'Rate limit exceeded'
                })
                return
            
            data = json.loads(message)
            
            if data.get('type') == 'execute_tool':
                tool = data.get('tool')
                target = data.get('target')
                user_id = data.get('user_id')
                tier = data.get('tier', 'essential')
                
                if not tool or not target:
                    await self.send_to_client(websocket, {
                        'type': 'error',
                        'message': 'Missing tool or target parameter'
                    })
                    return
                    
                # Execute tool in background
                asyncio.create_task(self.execute_tool(tool, target, websocket, user_id, tier))
                
            elif data.get('type') == 'ping':
                await self.send_to_client(websocket, {
                    'type': 'pong',
                    'timestamp': time.time()
                })
                
            else:
                await self.send_to_client(websocket, {
                    'type': 'error',
                    'message': 'Unknown message type'
                })
                
        except json.JSONDecodeError:
            await self.send_to_client(websocket, {
                'type': 'error',
                'message': 'Invalid JSON format'
            })
        except Exception as e:
            logger.error(f"Error handling message: {str(e)}")
            await self.send_to_client(websocket, {
                'type': 'error',
                'message': f'Server error: {str(e)}'
            })
    
    async def handle_client(self, websocket):
        """Handle a client connection"""
        await self.register_client(websocket)
        
        try:
            # Send welcome message
            await self.send_to_client(websocket, {
                'type': 'welcome',
                'message': 'Desktop Agent connected',
                'available_tools': list(ALLOWED_TOOLS.keys())
            })
            
            # Handle messages from client
            async for message in websocket:
                await self.handle_message(websocket, message)
                
        except websockets.exceptions.ConnectionClosed:
            logger.info("Client connection closed")
        except Exception as e:
            logger.error(f"Error in client handler: {e}")
        finally:
            await self.unregister_client(websocket)
    
    async def start_server(self):
        """Start the WebSocket server"""
        logger.info(f"Starting Desktop Agent on {self.host}:{self.port}")
        
        # Check if tools are available (will auto-install when needed)
        for tool_name, config in ALLOWED_TOOLS.items():
            if self.is_tool_available(tool_name):
                logger.info(f"✓ {tool_name} is available")
            else:
                logger.info(f"⚠ {tool_name} will be auto-installed when needed")
        
        # SECURITY: Start WebSocket server with enhanced security
        server = await websockets.serve(
            self.handle_client,
            self.host,
            self.port,
            ping_interval=30,
            ping_timeout=10,
            close_timeout=10,
            # SECURITY: Additional security settings
            max_size=SECURITY_CONFIG['max_message_size'],
            max_queue=32
        )
        
        logger.info(f"Desktop Agent is running on ws://{self.host}:{self.port}")
        logger.info(f"Available tools: {list(ALLOWED_TOOLS.keys())}")
        
        # Keep server running
        await server.wait_closed()

def main():
    """Main entry point"""
    agent = DesktopAgent()
    
    try:
        asyncio.run(agent.start_server())
    except KeyboardInterrupt:
        logger.info("Desktop Agent stopped by user")
    except Exception as e:
        logger.error(f"Desktop Agent error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Secure Desktop Agent - Backend Authentication Required
Agent must authenticate with backend before any operations
"""

import asyncio
import websockets
import json
import subprocess
import logging
import sys
import os
import shutil
import requests
import uuid
from typing import Dict, List, Any, Optional
import time
from datetime import datetime, timezone

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
BACKEND_URL = "https://api.pentorasec.com"  # Production Backend API URL
AGENT_ID = f"agent_{uuid.uuid4().hex[:8]}"  # Unique agent ID
AGENT_VERSION = "1.0.0"

# Simple tool configuration - NO VALIDATION
TOOLS = {
    'subfinder': {
        'command': 'subfinder',
        'args': ['-d', '{target}', '-silent']
    },
    'nmap': {
        'command': 'nmap',
        'args': ['-sS', '-sV', '-O', '-p', '21,22,23,25,53,80,110,143,443,993,995,3306,3389,5432,8080,8443', '{target}']
    },
    'gobuster': {
        'command': 'gobuster',
        'args': ['dir', '-u', '{target}', '-w', '/usr/share/wordlists/common.txt']
    },
    'ffuf': {
        'command': 'ffuf',
        'args': ['-u', '{target}/FUZZ', '-w', '/usr/share/wordlists/common.txt']
    },
    'nuclei': {
        'command': 'nuclei',
        'args': ['-u', '{target}', '-silent']
    },
    'amass': {
        'command': 'amass',
        'args': ['enum', '-d', '{target}']
    }
}

class SecureAgent:
    """Secure Agent - Must authenticate with backend before operations"""
    
    def __init__(self, host='localhost', port=13337):
        self.host = host
        self.port = port
        self.clients = set()
        self.auth_token = None
        self.refresh_token = None
        self.token_expires_at = None
        self.is_authenticated = False
        self.backend_websocket = None
        
    async def authenticate_with_backend(self) -> bool:
        """Authenticate with backend - REQUIRED before any operations"""
        try:
            logger.info("🔐 Authenticating with backend...")
            
            # First, try to register agent
            registration_data = {
                "agent_id": AGENT_ID,
                "agent_version": AGENT_VERSION,
                "user_agent": f"SecureAgent/{AGENT_VERSION}",
                "capabilities": list(TOOLS.keys())
            }
            
            # Register agent (this would normally require user authentication)
            # For now, we'll try to get a token directly
            auth_data = {
                "agent_id": AGENT_ID,
                "agent_url": "https://github.com/pentorasec/agent-simple.py"  # Required for integrity verification
            }
            
            response = requests.post(
                f"{BACKEND_URL}/api/agent/auth",
                json=auth_data,
                timeout=10
            )
            
            if response.status_code == 200:
                token_data = response.json()
                self.auth_token = token_data.get('token')
                self.token_expires_at = time.time() + token_data.get('expires_in', 900)
                self.is_authenticated = True
                
                logger.info("✅ Backend authentication successful")
                return True
            else:
                logger.error(f"❌ Backend authentication failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Backend authentication error: {e}")
            return False
    
    async def connect_to_backend_websocket(self) -> bool:
        """Connect to backend WebSocket with authentication"""
        try:
            if not self.is_authenticated:
                logger.error("❌ Not authenticated with backend")
                return False
            
            logger.info("🔌 Connecting to backend WebSocket...")
            
            # Connect to backend WebSocket
            self.backend_websocket = await websockets.connect(
                f"wss://api.pentorasec.com/ws/agent"
            )
            
            # Send authentication message
            auth_message = {
                "type": "auth",
                "token": self.auth_token,
                "agent_id": AGENT_ID
            }
            
            await self.backend_websocket.send(json.dumps(auth_message))
            
            # Wait for authentication response
            response = await self.backend_websocket.recv()
            response_data = json.loads(response)
            
            if response_data.get('type') == 'auth_success':
                logger.info("✅ Backend WebSocket authentication successful")
                return True
            else:
                logger.error(f"❌ Backend WebSocket authentication failed: {response_data}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Backend WebSocket connection error: {e}")
            return False
    
    async def register_client(self, websocket):
        """Register client - ONLY if authenticated with backend"""
        if not self.is_authenticated:
            await websocket.send(json.dumps({
                'type': 'error',
                'message': 'Agent not authenticated with backend'
            }))
            await websocket.close()
            return
        
        self.clients.add(websocket)
        logger.info(f"Client connected. Total clients: {len(self.clients)}")
        
    async def unregister_client(self, websocket):
        """Unregister client"""
        if websocket in self.clients:
            self.clients.discard(websocket)
            logger.info(f"Client disconnected. Total clients: {len(self.clients)}")
    
    async def send_to_client(self, websocket, message: Dict[str, Any]):
        """Send message to client - NO SIZE CHECKS"""
        try:
            await websocket.send(json.dumps(message))
        except websockets.exceptions.ConnectionClosed:
            await self.unregister_client(websocket)
        except Exception as e:
            logger.error(f"Error sending message: {str(e)}")
            await self.unregister_client(websocket)
    
    async def execute_tool(self, tool_name: str, target: str, websocket):
        """Execute tool - ONLY after backend validation"""
        
        # Check if authenticated
        if not self.is_authenticated:
            await self.send_to_client(websocket, {
                'type': 'error',
                'message': 'Agent not authenticated with backend'
            })
            return
        
        # Request tool execution permission from backend
        try:
            execution_request = {
                "tool_name": tool_name,
                "target": target,
                "args": TOOLS.get(tool_name, {}).get('args', []),
                "token": self.auth_token
            }
            
            response = requests.post(
                f"{BACKEND_URL}/api/agent/execute-tool",
                json=execution_request,
                timeout=10
            )
            
            if response.status_code != 200:
                await self.send_to_client(websocket, {
                    'type': 'error',
                    'message': f'Backend rejected tool execution: {response.text}'
                })
                return
            
            execution_data = response.json()
            if execution_data.get('status') != 'approved':
                await self.send_to_client(websocket, {
                    'type': 'error',
                    'message': f'Tool execution not approved: {execution_data.get("message")}'
                })
                return
            
        except Exception as e:
            logger.error(f"Backend tool execution request failed: {e}")
            await self.send_to_client(websocket, {
                'type': 'error',
                'message': 'Failed to get backend approval for tool execution'
            })
            return
        
        # Check if tool exists in our config
        if tool_name not in TOOLS:
            await self.send_to_client(websocket, {
                'type': 'error',
                'message': f'Tool "{tool_name}" not found'
            })
            return
        
        tool_config = TOOLS[tool_name]
        
        # Check if tool is available
        if not shutil.which(tool_config['command']):
            await self.send_to_client(websocket, {
                'type': 'error',
                'message': f'Tool "{tool_name}" not installed'
            })
            return
        
        # Prepare command
        command = [tool_config['command']]
        args = [arg.format(target=target) for arg in tool_config['args']]
        command.extend(args)
        
        logger.info(f"Executing (Backend Approved): {' '.join(command)}")
        
        # Send start message
        await self.send_to_client(websocket, {
            'type': 'start',
            'tool': tool_name,
            'target': target,
            'command': ' '.join(command),
            'execution_id': execution_data.get('execution_id')
        })
        
        try:
            # Execute command
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )
            
            # Stream output
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                    
                decoded_line = line.decode('utf-8', errors='ignore').strip()
                if decoded_line:
                    await self.send_to_client(websocket, {
                        'type': 'output',
                        'tool': tool_name,
                        'line': decoded_line
                    })
            
            # Wait for completion
            return_code = await process.wait()
            
            # Send completion message
            await self.send_to_client(websocket, {
                'type': 'complete',
                'tool': tool_name,
                'target': target,
                'return_code': return_code,
                'success': return_code == 0,
                'execution_id': execution_data.get('execution_id')
            })
            
        except FileNotFoundError:
            await self.send_to_client(websocket, {
                'type': 'error',
                'message': f'Tool "{tool_name}" not found'
            })
        except Exception as e:
            logger.error(f"Error executing {tool_name}: {str(e)}")
            await self.send_to_client(websocket, {
                'type': 'error',
                'message': f'Execution error: {str(e)}'
            })
    
    async def handle_message(self, websocket, message: str):
        """Handle message - NO VALIDATION, NO SECURITY CHECKS"""
        try:
            data = json.loads(message)
            
            if data.get('type') == 'execute_tool':
                tool = data.get('tool')
                target = data.get('target')
                
                if not tool or not target:
                    await self.send_to_client(websocket, {
                        'type': 'error',
                        'message': 'Missing tool or target parameter'
                    })
                    return
                
                # Execute tool - NO VALIDATION
                asyncio.create_task(self.execute_tool(tool, target, websocket))
                
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
        """Handle client connection - NO SECURITY CHECKS"""
        await self.register_client(websocket)
        
        try:
            # Send welcome message
            await self.send_to_client(websocket, {
                'type': 'welcome',
                'message': 'Simple Agent connected',
                'available_tools': list(TOOLS.keys())
            })
            
            # Handle messages
            async for message in websocket:
                await self.handle_message(websocket, message)
                
        except websockets.exceptions.ConnectionClosed:
            logger.info("Client connection closed")
        except Exception as e:
            logger.error(f"Error in client handler: {e}")
        finally:
            await self.unregister_client(websocket)
    
    async def start_server(self):
        """Start WebSocket server - ONLY after backend authentication"""
        logger.info(f"🚀 Starting Secure Agent on {self.host}:{self.port}")
        
        # CRITICAL: Authenticate with backend first
        logger.info("🔐 Step 1: Authenticating with backend...")
        if not await self.authenticate_with_backend():
            logger.error("❌ Failed to authenticate with backend. Agent cannot start.")
            sys.exit(1)
        
        logger.info("🔌 Step 2: Connecting to backend WebSocket...")
        if not await self.connect_to_backend_websocket():
            logger.error("❌ Failed to connect to backend WebSocket. Agent cannot start.")
            sys.exit(1)
        
        logger.info("✅ Step 3: Backend authentication complete. Starting local WebSocket server...")
        
        # Start WebSocket server
        server = await websockets.serve(
            self.handle_client,
            self.host,
            self.port,
            ping_interval=30,
            ping_timeout=10,
            close_timeout=10
        )
        
        logger.info(f"🎉 Secure Agent is running on ws://{self.host}:{self.port}")
        logger.info(f"🔧 Available tools: {list(TOOLS.keys())}")
        logger.info(f"🆔 Agent ID: {AGENT_ID}")
        logger.info("🛡️ All tool executions require backend approval")
        
        # Keep server running
        await server.wait_closed()

def main():
    """Main entry point"""
    agent = SecureAgent()
    
    try:
        asyncio.run(agent.start_server())
    except KeyboardInterrupt:
        logger.info("🛑 Secure Agent stopped by user")
    except Exception as e:
        logger.error(f"💥 Secure Agent error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()

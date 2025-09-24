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
import threading
import psutil
import platform
from pathlib import Path

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
    },
    'zap': {
        'command': 'zap.sh',
        'args': ['-daemon', '-port', '8080']
    }
}

class ZAPManager:
    """OWASP ZAP sürecini yöneten sınıf"""
    
    def __init__(self, port: int = 8787, api_key: str = "BIZIM_GUVENLI_ANAHTARIMIZ"):
        self.port = port
        self.api_key = api_key
        self.zap_process: Optional[subprocess.Popen] = None
        self.zap_executable: Optional[str] = None
        self.api_url = f"http://127.0.0.1:{port}"
        
        # ZAP executable'ını bul
        self.zap_executable = self._find_zap_executable()
        if not self.zap_executable:
            logger.error("❌ ZAP executable not found in agent bundle")
            raise FileNotFoundError("ZAP executable not found in agent bundle")
        
        logger.info(f"✅ ZAP Manager initialized - Port: {port}")
    
    def _find_zap_executable(self) -> Optional[str]:
        """Agent'ın kendi içindeki zap/ klasöründen ZAP executable'ını bul"""
        try:
            agent_dir = Path(__file__).parent.absolute()
            zap_dir = agent_dir / "zap"
            
            if not zap_dir.exists():
                logger.error(f"❌ ZAP directory not found: {zap_dir}")
                return None
            
            system = platform.system().lower()
            
            if system == "windows":
                zap_bat = zap_dir / "zap.bat"
                if zap_bat.exists():
                    return str(zap_bat)
            elif system in ["linux", "darwin"]:
                zap_sh = zap_dir / "zap.sh"
                if zap_sh.exists():
                    os.chmod(zap_sh, 0o755)
                    return str(zap_sh)
            
            return None
        except Exception as e:
            logger.error(f"❌ Error finding ZAP executable: {e}")
            return None
    
    def start(self) -> bool:
        """ZAP'ı daemon modunda başlat"""
        try:
            if self.is_running():
                logger.info("🔄 ZAP is already running")
                return True
            
            logger.info(f"🚀 Starting ZAP daemon on port {self.port}...")
            
            cmd = [
                self.zap_executable,
                "-daemon",
                f"-port", str(self.port),
                "-config", f"api.key={self.api_key}",
                "-config", "api.disablekey=false"
            ]
            
            self.zap_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=os.path.dirname(self.zap_executable)
            )
            
            logger.info(f"✅ ZAP process started with PID: {self.zap_process.pid}")
            
            # ZAP'ın başlamasını bekle
            for i in range(30):
                time.sleep(1)
                if self.is_running():
                    logger.info(f"✅ ZAP started successfully after {i+1} seconds")
                    return True
            
            logger.error("❌ ZAP failed to start within 30 seconds")
            return False
            
        except Exception as e:
            logger.error(f"❌ Error starting ZAP: {e}")
            return False
    
    def stop(self) -> bool:
        """Çalışan ZAP sürecini sonlandır"""
        try:
            if not self.zap_process:
                return True
            
            logger.info("🛑 Stopping ZAP daemon...")
            
            if self.zap_process.poll() is None:
                self.zap_process.terminate()
                time.sleep(2)
                if self.zap_process.poll() is None:
                    self.zap_process.kill()
            
            # Process tree'yi temizle
            try:
                if self.zap_process.pid:
                    parent = psutil.Process(self.zap_process.pid)
                    children = parent.children(recursive=True)
                    for child in children:
                        child.terminate()
                    psutil.wait_procs(children, timeout=3)
            except:
                pass
            
            self.zap_process = None
            logger.info("✅ ZAP daemon stopped")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error stopping ZAP: {e}")
            return False
    
    def is_running(self) -> bool:
        """ZAP'ın çalışıp çalışmadığını kontrol et"""
        try:
            endpoints = [
                f"{self.api_url}/JSON/core/view/version/",
                f"{self.api_url}/JSON/core/view/version",
                f"{self.api_url}/JSON/core/view/",
                f"{self.api_url}/"
            ]
            
            for endpoint in endpoints:
                try:
                    response = requests.get(
                        f"{endpoint}?apikey={self.api_key}",
                        timeout=3
                    )
                    if response.status_code == 200:
                        return True
                    
                    response = requests.get(endpoint, timeout=3)
                    if response.status_code == 200:
                        return True
                except:
                    continue
            
            return False
        except:
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """ZAP durumunu al"""
        try:
            if not self.is_running():
                return {
                    "running": False,
                    "port": self.port,
                    "api_url": self.api_url,
                    "error": "ZAP is not running"
                }
            
            return {
                "running": True,
                "port": self.port,
                "api_url": self.api_url,
                "pid": self.zap_process.pid if self.zap_process else None
            }
        except Exception as e:
            return {
                "running": False,
                "port": self.port,
                "api_url": self.api_url,
                "error": str(e)
            }
    
    def send_command(self, endpoint: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """ZAP API'ına komut gönder"""
        try:
            if not self.is_running():
                return {"error": "ZAP is not running"}
            
            url = f"{self.api_url}{endpoint}"
            if params is None:
                params = {}
            params["apikey"] = self.api_key
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                return response.json()
            else:
                return {
                    "error": f"HTTP {response.status_code}",
                    "response": response.text
                }
        except Exception as e:
            return {"error": str(e)}
    
    def __del__(self):
        """Destructor - ZAP'ı temizle"""
        try:
            self.stop()
        except:
            pass

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
        
        # ZAP Manager - Bundled ZAP management
        self.zap_manager = None
        self.zap_api_url = "http://127.0.0.1:8787"
        self.zap_api_key = "BIZIM_GUVENLI_ANAHTARIMIZ"
        self.zap_targets = []
        self.zap_scanning = False
        self.zap_monitoring_task = None
        
        # Legacy ZAP properties (for compatibility)
        self.zap_process = None
        
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
                "agent_url": "https://raw.githubusercontent.com/ismailbabu462/agent/main/agent-simple.py"  # Required for integrity verification
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
    
    # ==================== ZAP DAEMON FUNCTIONS ====================
    
    async def start_zap_daemon(self) -> bool:
        """Start ZAP daemon process using bundled ZAP Manager"""
        try:
            logger.info("🚀 Starting bundled ZAP daemon...")
            
            # Initialize ZAP Manager
            if not self.zap_manager:
                try:
                    self.zap_manager = ZAPManager(
                        port=8787,  # Use custom ZAP port
                        api_key=self.zap_api_key
                    )
                    logger.info("✅ ZAP Manager initialized")
                except Exception as e:
                    logger.error(f"❌ Failed to initialize ZAP Manager: {e}")
                    return False
            
            # Check if ZAP is already running
            if self.zap_manager.is_running():
                logger.info("✅ ZAP is already running")
                self.zap_api_url = self.zap_manager.api_url
                return True
            
            # Start ZAP using ZAP Manager
            logger.info("🚀 Starting ZAP using ZAP Manager...")
            if self.zap_manager.start():
                logger.info("✅ ZAP started successfully")
                self.zap_api_url = self.zap_manager.api_url
                return True
            else:
                logger.error("❌ Failed to start ZAP using ZAP Manager")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error starting ZAP daemon: {e}")
            return False
    
    async def test_zap_connection(self) -> bool:
        """Test ZAP API connection"""
        try:
            response = requests.get(f"{self.zap_api_url}/JSON/core/view/version/", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    async def stop_zap_daemon(self):
        """Stop ZAP daemon process"""
        try:
            # Stop ZAP using ZAP Manager
            if self.zap_manager:
                logger.info("🛑 Stopping ZAP daemon using ZAP Manager...")
                if self.zap_manager.stop():
                    logger.info("✅ ZAP daemon stopped via ZAP Manager")
                else:
                    logger.warning("⚠️ Failed to stop ZAP via ZAP Manager")
            
            # Legacy ZAP process cleanup
            if self.zap_process:
                logger.info("🛑 Stopping legacy ZAP daemon...")
                self.zap_process.terminate()
                self.zap_process.wait(timeout=10)
                self.zap_process = None
                logger.info("✅ Legacy ZAP daemon stopped")
                
        except Exception as e:
            logger.error(f"❌ Error stopping ZAP daemon: {e}")
    
    def send_zap_command(self, endpoint: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        ZAP API'ına komut gönder
        
        Args:
            endpoint: API endpoint'i
            params: Ek parametreler
            
        Returns:
            API yanıtı
        """
        try:
            if self.zap_manager:
                return self.zap_manager.send_command(endpoint, params)
            else:
                return {"error": "ZAP Manager not initialized"}
        except Exception as e:
            return {"error": str(e)}
    
    async def add_zap_target(self, target: str) -> bool:
        """Add target to ZAP scanning list"""
        try:
            if target not in self.zap_targets:
                self.zap_targets.append(target)
                logger.info(f"🎯 Added target to ZAP: {target}")
                
                # Notify backend
                if self.backend_websocket:
                    await self.backend_websocket.send(json.dumps({
                        'type': 'zap_target_added',
                        'target': target,
                        'agent_id': AGENT_ID
                    }))
                
                return True
            return False
        except Exception as e:
            logger.error(f"❌ Error adding ZAP target: {e}")
            return False
    
    async def remove_zap_target(self, target: str) -> bool:
        """Remove target from ZAP scanning list"""
        try:
            if target in self.zap_targets:
                self.zap_targets.remove(target)
                logger.info(f"🗑️ Removed target from ZAP: {target}")
                
                # Notify backend
                if self.backend_websocket:
                    await self.backend_websocket.send(json.dumps({
                        'type': 'zap_target_removed',
                        'target': target,
                        'agent_id': AGENT_ID
                    }))
                
                return True
            return False
        except Exception as e:
            logger.error(f"❌ Error removing ZAP target: {e}")
            return False
    
    async def start_zap_scan(self, target: str) -> bool:
        """Start ZAP scan for specific target"""
        try:
            if not await self.test_zap_connection():
                logger.error("❌ ZAP daemon not running")
                return False
            
            logger.info(f"🔍 Starting ZAP scan for: {target}")
            
            # Start spider scan
            spider_response = requests.get(
                f"{self.zap_api_url}/JSON/spider/action/scan/",
                params={'url': target, 'maxChildren': 10, 'recurse': 'true'},
                timeout=10
            )
            
            if spider_response.status_code == 200:
                spider_id = spider_response.json().get('scan')
                logger.info(f"🕷️ Spider scan started with ID: {spider_id}")
                
                # Start active scan after spider completes
                await asyncio.sleep(5)  # Wait a bit
                
                active_response = requests.get(
                    f"{self.zap_api_url}/JSON/ascan/action/scan/",
                    params={'url': target, 'recurse': 'true'},
                    timeout=10
                )
                
                if active_response.status_code == 200:
                    active_id = active_response.json().get('scan')
                    logger.info(f"⚡ Active scan started with ID: {active_id}")
                    
                    # Start monitoring task
                    if not self.zap_monitoring_task:
                        self.zap_monitoring_task = asyncio.create_task(self.monitor_zap_scans())
                    
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"❌ Error starting ZAP scan: {e}")
            return False
    
    async def monitor_zap_scans(self):
        """Monitor ZAP scans and send results to backend"""
        try:
            while True:
                await asyncio.sleep(30)  # Check every 30 seconds
                
                if not await self.test_zap_connection():
                    continue
                
                # Get alerts (vulnerabilities)
                alerts_response = requests.get(
                    f"{self.zap_api_url}/JSON/core/view/alerts/",
                    timeout=5
                )
                
                if alerts_response.status_code == 200:
                    alerts = alerts_response.json().get('alerts', [])
                    
                    for alert in alerts:
                        # Send vulnerability to backend
                        vulnerability_data = {
                            'type': 'zap_vulnerability',
                            'agent_id': AGENT_ID,
                            'vulnerability': {
                                'name': alert.get('name', 'Unknown'),
                                'risk': alert.get('risk', 'Unknown'),
                                'url': alert.get('url', ''),
                                'description': alert.get('description', ''),
                                'solution': alert.get('solution', ''),
                                'reference': alert.get('reference', ''),
                                'cweid': alert.get('cweid', ''),
                                'wascid': alert.get('wascid', ''),
                                'timestamp': datetime.now().isoformat()
                            }
                        }
                        
                        if self.backend_websocket:
                            await self.backend_websocket.send(json.dumps(vulnerability_data))
                
        except Exception as e:
            logger.error(f"❌ Error monitoring ZAP scans: {e}")
    
    async def get_zap_status(self) -> Dict[str, Any]:
        """Get ZAP daemon status"""
        try:
            status = {
                'running': False,
                'version': None,
                'targets': self.zap_targets,
                'scanning': self.zap_scanning
            }
            
            if await self.test_zap_connection():
                status['running'] = True
                
                # Get ZAP version
                version_response = requests.get(
                    f"{self.zap_api_url}/JSON/core/view/version/",
                    timeout=5
                )
                
                if version_response.status_code == 200:
                    status['version'] = version_response.json().get('version')
            
            return status
            
        except Exception as e:
            logger.error(f"❌ Error getting ZAP status: {e}")
            return {'running': False, 'error': str(e)}
    
    # ==================== END ZAP FUNCTIONS ====================
    
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
            
            # ZAP Commands
            elif data.get('type') == 'start_zap_daemon':
                success = await self.start_zap_daemon()
                await self.send_to_client(websocket, {
                    'type': 'zap_daemon_started',
                    'success': success
                })
            
            elif data.get('type') == 'stop_zap_daemon':
                await self.stop_zap_daemon()
                await self.send_to_client(websocket, {
                    'type': 'zap_daemon_stopped',
                    'success': True
                })
            
            elif data.get('type') == 'add_zap_target':
                target = data.get('target')
                if target:
                    success = await self.add_zap_target(target)
                    await self.send_to_client(websocket, {
                        'type': 'zap_target_added',
                        'target': target,
                        'success': success
                    })
                else:
                    await self.send_to_client(websocket, {
                        'type': 'error',
                        'message': 'Missing target parameter'
                    })
            
            elif data.get('type') == 'remove_zap_target':
                target = data.get('target')
                if target:
                    success = await self.remove_zap_target(target)
                    await self.send_to_client(websocket, {
                        'type': 'zap_target_removed',
                        'target': target,
                        'success': success
                    })
                else:
                    await self.send_to_client(websocket, {
                        'type': 'error',
                        'message': 'Missing target parameter'
                    })
            
            elif data.get('type') == 'start_zap_scan':
                target = data.get('target')
                if target:
                    success = await self.start_zap_scan(target)
                    await self.send_to_client(websocket, {
                        'type': 'zap_scan_started',
                        'target': target,
                        'success': success
                    })
                else:
                    await self.send_to_client(websocket, {
                        'type': 'error',
                        'message': 'Missing target parameter'
                    })
            
            elif data.get('type') == 'get_zap_status':
                status = await self.get_zap_status()
                await self.send_to_client(websocket, {
                    'type': 'zap_status',
                    'status': status
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
        
        # Step 4: Start ZAP daemon (optional)
        logger.info("🔍 Step 4: Starting ZAP daemon...")
        await self.start_zap_daemon()
        
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

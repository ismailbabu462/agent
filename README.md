# Desktop Agent

The Desktop Agent is a WebSocket server that runs locally on your machine and executes pentest tools directly. This provides better security and performance compared to running tools on the remote server.

## Features

- **Local Execution**: Tools run on your local machine, not on the server
- **Real-time Output**: Stream tool output in real-time via WebSocket
- **Security Whitelist**: Only allows pre-approved tools to be executed
- **Input Validation**: Validates targets to prevent command injection
- **Multi-client Support**: Multiple frontend connections supported

## Installation

1. Install Python dependencies:
```bash
cd DesktopAgent
pip install -r requirements.txt
```

2. Install pentest tools on your system:
   - **Subfinder**: `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
   - **Nmap**: `sudo apt install nmap` (Ubuntu/Debian) or `brew install nmap` (macOS)
   - **Gobuster**: `go install github.com/OJ/gobuster/v3@latest`
   - **FFuF**: `go install github.com/ffuf/ffuf@latest`
   - **Nuclei**: `go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest`
   - **Amass**: `go install -v github.com/owasp-amass/amass/v3/...@latest`

## Usage

1. Start the Desktop Agent:
```bash
python agent.py
```

2. The agent will start a WebSocket server on `localhost:13337`

3. Open the frontend application and navigate to the Tools page

4. The frontend will automatically connect to the Desktop Agent

5. Enter a target and click "Run Tool" to execute pentest tools locally

## Supported Tools

- **Subfinder**: Fast passive subdomain discovery
- **Nmap**: Network discovery and port scanning
- **Gobuster**: Directory and file brute-forcing
- **FFuF**: Fast web fuzzer
- **Nuclei**: Fast vulnerability scanner
- **Amass**: In-depth attack surface mapping

## Security Features

- **Tool Whitelist**: Only pre-approved tools can be executed
- **Input Validation**: Targets are validated to prevent command injection
- **Local Execution**: Tools run on your machine, not on remote servers
- **WebSocket Authentication**: Secure communication with the frontend

## Configuration

The agent can be configured by modifying the `ALLOWED_TOOLS` dictionary in `agent.py`:

```python
ALLOWED_TOOLS = {
    'tool_name': {
        'command': 'command_name',
        'args': ['arg1', 'arg2', '{target}'],
        'description': 'Tool description'
    }
}
```

## Troubleshooting

### Connection Issues
- Ensure the agent is running on `localhost:13337`
- Check firewall settings
- Verify WebSocket support in your browser

### Tool Not Found
- Install the required tool on your system
- Check if the tool is in your PATH
- Verify the tool name in the `ALLOWED_TOOLS` configuration

### Permission Issues
- Some tools may require elevated privileges
- Run the agent with appropriate permissions if needed

## Development

To add a new tool:

1. Add the tool to the `ALLOWED_TOOLS` dictionary
2. Test the tool execution locally
3. Update the frontend tool mapping if needed

## License

This project is part of the Pentest Suite and follows the same license terms.

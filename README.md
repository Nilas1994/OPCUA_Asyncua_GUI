# OPC UA Client Application

A comprehensive Python-based OPC UA client application with GUI, built using PyQt5 and asyncua. This application provides a user-friendly interface for connecting to OPC UA servers, browsing nodes, managing subscriptions, and registering nodes with special behaviors.

![OPC UA Client Screenshot](screenshot.png)

## Features

### Core Functionality
- Connect to OPC UA servers with various security policies
- Browse OPC UA node hierarchy
- Subscribe to node data changes
- Register nodes for writing and special behaviors
- Support for extension objects and complex data types
- Auto-reconnection with configurable backoff
- JSON-based output for external integration

### Security Features
- Support for multiple security policies (Basic128Rsa15, Basic256, Basic256Sha256, AES128Sha256RsaOaep, AES256Sha256RsaPss)
- Username/password authentication with secure keyring storage
- X.509 certificate generation and management
- Certificate validation and secure communication

### Node Management
- **Standard Nodes**: Regular OPC UA nodes with read/write capabilities
- **LiveBit Nodes**: Automatically toggle boolean values at configured intervals
- **Toggle Nodes**: Manually toggle boolean values
- **Custom Nodes**: File-based control for external integration
- Support for complex data types including extension objects

### External Integration
- JSON file-based control system
- File monitoring for automatic updates
- External tools can edit JSON files to control nodes
- Automatic write processing with conflict detection

## Installation

### Requirements
- Python 3.7+
- PyQt5
- asyncua
- keyring
- cryptography

### Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/opcua-client.git
cd opcua-client

# Install dependencies
pip install PyQt5 asyncua keyring cryptography

# Run the application
python main.py
```

## Directory Structure
```
opcua-client/
├── main.py                  # Application entry point
├── gui_app.py              # Main GUI application
├── client_core.py          # OPC UA client core functionality
├── config_manager.py       # Configuration management
├── json_output_manager.py  # JSON output handling
├── file_watcher.py         # File system monitoring
├── node_manager.py         # Node behavior management
├── extension_objects.py    # Extension object handling
├── utils.py                # Utility functions
└── README.md               # This file
```

## Configuration

The application stores its configuration in `~/.opcua-client/config/config.json`:

```json
{
  "endpoint": "opc.tcp://localhost:4840",
  "username": "",
  "auto_connect": false,
  "security_policy": "NO_SECURITY",
  "auto_reconnect": true,
  "reconnect_delay": 5,
  "max_reconnect_delay": 60,
  "max_reconnect_attempts": 0,
  "json_output_dir": "~/.opcua-client/output"
}
```

## Usage

### Basic Operation

1. **Connect to Server**
   - Enter OPC UA server endpoint
   - Select security policy
   - Configure authentication if needed
   - Click "Connect"

2. **Browse Nodes**
   - Use the browser tab to navigate the node hierarchy
   - Click on nodes to view details and references
   - Right-click to access context menu options

3. **Subscribe to Nodes**
   - Select a variable node
   - Click "Subscribe" to monitor data changes
   - View real-time data in the Subscriptions tab

4. **Register Nodes**
   - Select a variable node
   - Click "Register" to enable writing
   - Configure node type and behavior
   - Use the write controls to update values

### External File Control

The application supports external control through JSON files in the `custom` directory:

```json
{
  "node_id": "ns=2;s=MyNode",
  "display_name": "My Node",
  "node_type": "Custom",
  "data_type": "Boolean",
  "value": true,
  "metadata": {
    "write_requested": true,  // Set to true to request write
    "last_updated": "2025-05-04T12:00:00"
  }
}
```

To write a value:
1. Set `value` to desired value
2. Set `metadata.write_requested` to `true`
3. Save the file
4. Application will detect change and write to OPC UA server
5. `write_requested` will be reset to `false` automatically

### Node Types

1. **Standard**: Regular read/write nodes
2. **LiveBit**: Auto-toggle boolean values at intervals
3. **Toggle**: Manually toggle boolean values
4. **Custom**: File-based control from external applications

### Logging

Logs are stored in `~/.opcua-client/logs/opcua_client.log` with rotation:
- Maximum file size: 10MB
- Keeps last 5 files
- Available in the Log tab for real-time monitoring

## Advanced Features

### Certificate Management
- Generate self-signed certificates
- Configure certificate details (CN, Organization, etc.)
- Automatic certificate/key pairing

### Reconnection Strategy
- Exponential backoff with jitter
- Configurable maximum attempts
- Automatic subscription restoration

### Extension Objects
- Automatic data type dictionary loading
- Complex structure support
- Custom object decoding

## Troubleshooting

### Common Issues

1. **Connection Timeout**
   - Verify server endpoint is correct
   - Check network connectivity
   - Ensure server is running

2. **Security Errors**
   - Verify certificate paths
   - Check security policy compatibility
   - Ensure proper permissions

3. **File Monitoring Not Working**
   - Check output directory permissions
   - Verify custom nodes directory exists
   - Monitor the Log tab for errors

### Debug Mode
Enable debug logging by setting environment variable:
```bash
export OPCUA_DEBUG=1
python main.py
```

## Development

### Adding New Node Types
1. Extend `NodeType` enum in `node_manager.py`
2. Implement behavior in `process_livebit_nodes()` or similar
3. Update GUI controls accordingly

### Custom Extension Objects
Override `decode_extension_object()` in `extension_objects.py` for custom handling.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or create issues for bugs and feature requests.

### Code Style
- Follow PEP 8 guidelines
- Use type hints where appropriate
- Add docstrings to all public methods
- Include unit tests for new features

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [asyncua](https://github.com/FreeOpcUa/opcua-asyncio) - The async OPC UA library used
- [PyQt5](https://www.riverbankcomputing.com/static/Docs/PyQt5/) - GUI framework
- All contributors and users of this project

## Support

For support, please:
1. Check the [Wiki](https://github.com/yourusername/opcua-client/wiki)
2. Search [Issues](https://github.com/yourusername/opcua-client/issues)
3. Create a new issue if needed

## Authors

- Your Name (@yourusername)

## Version History

- 1.0.0 - Initial release
  - Core OPC UA functionality
  - GUI interface
  - Security support
  - JSON export/import
  - File monitoring system

## Screenshots

### Main Connection Tab
![Connection Tab](docs/screenshots/connection.png)

### Node Browser
![Browser Tab](docs/screenshots/browser.png)

### File Monitoring
![Output Tab](docs/screenshots/output.png)

## Future Roadmap

- [ ] MQTT bridge integration
- [ ] REST API for external control
- [ ] Data logging to database
- [ ] Alarm and event support
- [ ] Historical data collection
- [ ] Custom dashboard creation

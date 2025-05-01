# OPC UA Client

A robust OPC UA client application built with Python using the asyncua library and PyQt5 for the GUI.

# OPC UA Client Project Structure

```
opcua-client/
├── config/
│   └── default_config.json      # Default configuration template
├── main.py                      # Main application entry point
├── client.py                    # OPC UA client implementation
├── config_handler.py            # Configuration management
├── gui/
│   ├── __init__.py
│   ├── main_window.py           # Main application window
│   ├── connection_dialog.py     # Connection configuration dialog
│   ├── browser_widget.py        # Node browser widget
│   ├── registered_nodes.py      # Registered nodes widget
│   ├── subscriptions.py         # Subscriptions widget
│   ├── output.py                # Output widget for data export
│   ├── style.py                 # Dark mode styling
│   └── resources/               # UI resources (icons, etc.)
├── security/
│   ├── __init__.py
│   └── certificate.py           # Certificate management
├── utils/
│   ├── __init__.py
│   └── logger.py                # Logging utilities
└── requirements.txt             # Project dependencies
```

## Features

- Modern dark mode GUI with PyQt5
- Asynchronous OPC UA communication with asyncua library
- Secure credential storage with keyring
- Comprehensive node browsing capabilities
- Support for all major security policies
- Subscription management
- Node registration and monitoring
- LiveBit functionality for boolean nodes
- Data export in multiple formats
- Automatic reconnection
- Detailed logging

## Installation

### Prerequisites

- Python 3.8 or higher
- PyQt5
- asyncua library
- keyring

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/opcua-client.git
cd opcua-client
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python main.py
```

## Usage

### Connection

1. Go to File > Connect or use the toolbar button
2. Enter the OPC UA server endpoint URL (e.g., opc.tcp://localhost:4840/)
3. Configure security settings if required
4. Click OK to establish connection

### Node Browsing

- The Browser tab displays the OPC UA address space
- Expand nodes to navigate through the address space
- Click on a node to view its attributes, references, and value
- Right-click on a node for additional options

### Registering Nodes

- Select a node in the Browser tab
- Click the "Register" button or use right-click menu
- Enter a name for the registered node
- Registered nodes appear in the Registered Nodes tab for quick access

### LiveBit Functionality

- In the Registered Nodes tab, select a boolean node
- Click "Toggle LiveBit" to start the LiveBit functionality
- The value will toggle between true and false at the specified interval

### Subscriptions

- Select a node in the Browser tab
- Click "Subscribe" to create a subscription for that node
- Data changes will appear in the Subscriptions tab
- Configure the publishing interval in the Subscription tab

### Data Export

- In the Output tab, configure export settings (format, directory)
- Click "Export Now" to manually export data
- Enable automatic export with a specified interval

## Configuration

The configuration is stored in `~/.opcua_client/config/config.json`. You can modify this file directly or use the application UI to change settings.

## Security

- Credentials are stored securely using the system's keyring
- Certificates are stored in `~/.opcua_client/certs/`
- Supports all security policies defined in the OPC UA specification

## License

[MIT License](LICENSE)

## Acknowledgments

- Based on the [asyncua](https://github.com/FreeOpcUa/opcua-asyncio) library
- Inspired by UaExpert and other OPC UA clients
# Installation Guide for OPC UA Client

This guide will help you install and run the OPC UA Client application.

## Prerequisites

Before installing the OPC UA Client, make sure you have the following prerequisites:

1. **Python 3.8 or higher** - The application is built with Python, so you need to have Python installed on your system. You can download it from [python.org](https://www.python.org/downloads/).

2. **pip** - The Python package installer, which is included with Python installations from Python 3.4 onwards.

3. **Git** (optional) - If you want to clone the repository directly. Otherwise, you can download a zip file.

## Installation Steps

### Step 1: Get the Code

Either clone the repository using Git:

```bash
git clone https://github.com/yourusername/opcua-client.git
cd opcua-client
```

Or download and extract the zip file from the repository.

### Step 2: Create a Virtual Environment (Optional but Recommended)

It's good practice to create a virtual environment for your Python projects to avoid dependency conflicts:

```bash
# On Windows
python -m venv venv
venv\Scripts\activate

# On macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

Install all the required dependencies using pip:

```bash
pip install -r requirements.txt
```

This will install:
- asyncua
- PyQt5
- keyring
- cryptography
- python-dateutil
- qasync

### Step 4: Run the Application

Now you can run the application:

```bash
python main.py
```

## Troubleshooting Common Issues

### Missing Dependencies

If you encounter errors about missing modules, make sure you've installed all dependencies:

```bash
pip install -r requirements.txt
```

### Permission Issues with keyring

On some systems, you might encounter permission issues with the keyring library. This is usually related to system keyring access. You can try:

```bash
pip install keyrings.alt
```

This provides alternative keyring backends that don't require system privileges.

### PyQt5 Installation Issues

If you have problems installing PyQt5:

- On Ubuntu/Debian: `sudo apt-get install python3-pyqt5`
- On macOS: `brew install pyqt@5`
- On Windows: Make sure you have the Microsoft Visual C++ Redistributable installed

### Certificate Generation Errors

If you encounter issues with certificate generation, ensure you have the cryptography package installed correctly:

```bash
pip uninstall cryptography
pip install cryptography
```

## Testing with a Local OPC UA Server

For testing, you can use the Simple OPC UA Server included with the asyncua library:

```bash
# Install the asyncua package if not already installed
pip install asyncua

# Run a test server
python -m asyncua.examples.server_minimal
```

This will start a simple OPC UA server at `opc.tcp://localhost:4840/freeopcua/server/` which you can connect to with the client.

## Next Steps

After installation, check out the [User Guide](USER_GUIDE.md) for instructions on how to use the OPC UA Client.

## Support

If you encounter any issues that are not covered in this guide, please file an issue on the GitHub repository.
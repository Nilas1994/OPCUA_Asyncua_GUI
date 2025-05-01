#!/usr/bin/env python3
"""
Main window for OPC UA Client
"""
import os
import asyncio
import logging
import keyring
from pathlib import Path
from typing import Optional, Dict, List

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, 
    QAction, QToolBar, QStatusBar, QLabel, QPushButton, QFileDialog,
    QMessageBox, QDockWidget, QTextEdit, QMenu, QSplitter,
    QApplication
)
from PyQt5.QtCore import Qt, pyqtSignal, pyqtSlot, QSize, QSettings
from PyQt5.QtGui import QIcon, QPixmap

from asyncua import ua

from gui.connection_dialog import ConnectionDialog
from gui.browser_widget import BrowserWidget
from gui.registered_nodes import RegisteredNodesWidget
from gui.subscriptions import SubscriptionsWidget
from gui.output import OutputWidget
from client import OpcUaClient, ConnectionStatus
from utils.logger import QLogHandler

logger = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    """Main application window"""
    
    # Signals to bridge between asyncio and Qt
    connect_signal = pyqtSignal(str, str, str, str, str, str)
    disconnect_signal = pyqtSignal()
    browse_node_signal = pyqtSignal(object)
    read_node_signal = pyqtSignal(object)
    write_node_signal = pyqtSignal(object, object)
    read_attributes_signal = pyqtSignal(object)
    read_references_signal = pyqtSignal(object)
    subscribe_signal = pyqtSignal(list, int, str)
    unsubscribe_signal = pyqtSignal(str)
    register_node_signal = pyqtSignal(object, str)
    unregister_node_signal = pyqtSignal(str)
    start_livebit_signal = pyqtSignal(str, int)
    stop_livebit_signal = pyqtSignal(str)
    save_registered_nodes_signal = pyqtSignal(str)
    load_registered_nodes_signal = pyqtSignal(str)
    
    def __init__(self, config_handler):
        """Initialize the main window
        
        Args:
            config_handler: Configuration handler instance
        """
        super().__init__()
        self.config = config_handler
        self.client = OpcUaClient()
        
        # Get application path
        self.app_dir = Path.home() / ".opcua_client"
        self.nodes_dir = self.app_dir / "nodes"
        
        # Set up UI
        self.setWindowTitle("OPC UA Client")
        self.setMinimumSize(1024, 768)
        
        # Restore window geometry from config
        self._restore_geometry()
        
        # Create central widget and main layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        self.main_layout.addWidget(self.tab_widget)
        
        # Create widgets for tabs
        self.init_browser_tab()
        self.init_registered_nodes_tab()
        self.init_subscriptions_tab()
        self.init_output_tab()
        
        # Create log dock widget
        self.init_log_dock()
        
        # Create status bar
        self.init_status_bar()
        
        # Create menus and toolbar
        self.init_menus()
        self.init_toolbar()
        
        # Connect signals/slots
        self.connect_signals()
        
        # Set up log handler to redirect logs to log view
        self.log_handler = QLogHandler(self.log_message)
        self.log_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s'))
        self.log_handler.setLevel(logging.INFO)
        logging.getLogger().addHandler(self.log_handler)
        
        # Restore last active tab
        last_tab = self.config.get("ui", "last_active_tab")
        if last_tab is not None and last_tab < self.tab_widget.count():
            self.tab_widget.setCurrentIndex(last_tab)
            
        # Auto-connect if configured
        endpoint = self.config.get("connection", "endpoint")
        auto_reconnect = self.config.get("connection", "auto_reconnect")
        if endpoint and auto_reconnect:
            # Schedule auto-connect using a timer to allow the event loop to start first
            from PyQt5.QtCore import QTimer
            QTimer.singleShot(1000, self.try_auto_connect)

    def try_auto_connect(self):
        """Start auto-connect process after UI is shown"""
        # Now we can safely create an asyncio task
        asyncio.create_task(self.auto_connect())
        
    def _restore_geometry(self):
        """Restore window geometry from config"""
        window_size = self.config.get("ui", "window_size")
        window_position = self.config.get("ui", "window_position")
        
        if window_size:
            self.resize(window_size[0], window_size[1])
        if window_position:
            self.move(window_position[0], window_position[1])
    
    def _save_geometry(self):
        """Save window geometry to config"""
        self.config.set("ui", "window_size", [self.width(), self.height()])
        self.config.set("ui", "window_position", [self.x(), self.y()])
        self.config.set("ui", "last_active_tab", self.tab_widget.currentIndex())
    
    def init_browser_tab(self):
        """Initialize browser tab"""
        self.browser_widget = BrowserWidget(self.client)
        self.tab_widget.addTab(self.browser_widget, "Browser")
    
    def init_registered_nodes_tab(self):
        """Initialize registered nodes tab"""
        self.registered_nodes_widget = RegisteredNodesWidget(self.client)
        self.tab_widget.addTab(self.registered_nodes_widget, "Registered Nodes")
    
    def init_subscriptions_tab(self):
        """Initialize subscriptions tab"""
        self.subscriptions_widget = SubscriptionsWidget(self.client)
        self.tab_widget.addTab(self.subscriptions_widget, "Subscriptions")
    
    def init_output_tab(self):
        """Initialize output tab"""
        self.output_widget = OutputWidget(self.client)
        self.tab_widget.addTab(self.output_widget, "Output")
    
    def init_log_dock(self):
        """Initialize log dock widget"""
        self.log_dock = QDockWidget("Log", self)
        self.log_dock.setAllowedAreas(Qt.BottomDockWidgetArea | Qt.TopDockWidgetArea)
        self.log_dock.setFeatures(QDockWidget.DockWidgetMovable | QDockWidget.DockWidgetFloatable)
        
        # Create log text edit
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setLineWrapMode(QTextEdit.NoWrap)
        self.log_text.document().setMaximumBlockCount(1000)  # Limit to 1000 lines
        
        # Set dark style for log text
        self.log_text.setStyleSheet("""
            QTextEdit {
                background-color: #1a1a1a;
                color: #cccccc;
                font-family: monospace;
            }
        """)
        
        self.log_dock.setWidget(self.log_text)
        self.addDockWidget(Qt.BottomDockWidgetArea, self.log_dock)
    
    def init_status_bar(self):
        """Initialize status bar"""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Create status items
        self.connection_status_label = QLabel("Disconnected")
        self.connection_status_label.setProperty("connectionStatus", "disconnected")
        
        self.endpoint_label = QLabel("No Endpoint")
        
        # Add items to status bar
        self.status_bar.addWidget(QLabel("Connection:"))
        self.status_bar.addWidget(self.connection_status_label)
        self.status_bar.addWidget(QLabel(" | "))
        self.status_bar.addWidget(QLabel("Endpoint:"))
        self.status_bar.addWidget(self.endpoint_label)
        
        # Add stretch to push additional info to the right
        self.status_bar.addPermanentWidget(QLabel("Ready"))
    
    def init_menus(self):
        """Initialize menus"""
        # Create menu bar
        self.menu_bar = self.menuBar()
        
        # Create File menu
        self.file_menu = self.menu_bar.addMenu("&File")
        
        # Create Connect action
        self.connect_action = QAction("&Connect...", self)
        self.connect_action.setShortcut("Ctrl+N")
        self.connect_action.setStatusTip("Connect to OPC UA Server")
        self.connect_action.triggered.connect(self.show_connect_dialog)
        self.file_menu.addAction(self.connect_action)
        
        # Create Disconnect action
        self.disconnect_action = QAction("&Disconnect", self)
        self.disconnect_action.setShortcut("Ctrl+D")
        self.disconnect_action.setStatusTip("Disconnect from OPC UA Server")
        self.disconnect_action.triggered.connect(self.confirm_disconnect)
        self.disconnect_action.setEnabled(False)
        self.file_menu.addAction(self.disconnect_action)
        
        self.file_menu.addSeparator()
        
        # Create Exit action
        self.exit_action = QAction("E&xit", self)
        self.exit_action.setShortcut("Ctrl+Q")
        self.exit_action.setStatusTip("Exit the application")
        self.exit_action.triggered.connect(self.close)
        self.file_menu.addAction(self.exit_action)
        
        # Create Tools menu
        self.tools_menu = self.menu_bar.addMenu("&Tools")
        
        # Create Save Registered Nodes action
        self.save_nodes_action = QAction("&Save Registered Nodes", self)
        self.save_nodes_action.setStatusTip("Save registered nodes to files")
        self.save_nodes_action.triggered.connect(
            lambda: self.save_registered_nodes_signal.emit(str(self.nodes_dir))
        )
        self.tools_menu.addAction(self.save_nodes_action)
        
        # Create Load Registered Nodes action
        self.load_nodes_action = QAction("&Load Registered Nodes", self)
        self.load_nodes_action.setStatusTip("Load registered nodes from files")
        self.load_nodes_action.triggered.connect(
            lambda: self.load_registered_nodes_signal.emit(str(self.nodes_dir))
        )
        self.tools_menu.addAction(self.load_nodes_action)
        
        self.tools_menu.addSeparator()
        
        # Create Certificate Manager action
        self.cert_manager_action = QAction("&Certificate Manager...", self)
        self.cert_manager_action.setStatusTip("Manage OPC UA Certificates")
        self.cert_manager_action.triggered.connect(self.show_certificate_manager)
        self.tools_menu.addAction(self.cert_manager_action)
        
        # Create Clear Log action
        self.clear_log_action = QAction("Clear &Log", self)
        self.clear_log_action.setStatusTip("Clear log view")
        self.clear_log_action.triggered.connect(self.log_text.clear)
        self.tools_menu.addAction(self.clear_log_action)
        
        # Create View menu
        self.view_menu = self.menu_bar.addMenu("&View")
        
        # Create Show/Hide Log action
        self.toggle_log_action = QAction("Show/Hide &Log", self)
        self.toggle_log_action.setShortcut("Ctrl+L")
        self.toggle_log_action.setStatusTip("Show or hide log view")
        self.toggle_log_action.triggered.connect(
            lambda: self.log_dock.setVisible(not self.log_dock.isVisible())
        )
        self.view_menu.addAction(self.toggle_log_action)
        
        # Create Help menu
        self.help_menu = self.menu_bar.addMenu("&Help")
        
        # Create About action
        self.about_action = QAction("&About", self)
        self.about_action.setStatusTip("Show about dialog")
        self.about_action.triggered.connect(self.show_about_dialog)
        self.help_menu.addAction(self.about_action)
    
    def init_toolbar(self):
        """Initialize toolbar"""
        self.toolbar = QToolBar("Main Toolbar")
        self.toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(self.toolbar)
        
        # Add Connect action to toolbar
        self.toolbar.addAction(self.connect_action)
        
        # Add Disconnect action to toolbar
        self.toolbar.addAction(self.disconnect_action)
        
        self.toolbar.addSeparator()
        
        # Add tabs to toolbar for quick navigation
        for i in range(self.tab_widget.count()):
            tab_action = QAction(self.tab_widget.tabText(i), self)
            tab_action.triggered.connect(lambda checked, index=i: self.tab_widget.setCurrentIndex(index))
            self.toolbar.addAction(tab_action)
    
    def connect_signals(self):
        """Connect signals and slots"""
        # Connect tab widget signals
        self.tab_widget.currentChanged.connect(self.on_tab_changed)
        
        # Connect client signals to GUI updates
        self.client.connection_status_changed.connect(self.on_connection_status_changed)
        self.client.connection_established.connect(self.on_connection_established)
        self.client.connection_lost.connect(self.on_connection_lost)
        self.client.log_message.connect(self.log_message)
        
        # Connect GUI signals to client methods
        self.connect_signal.connect(self.on_connect)
        self.disconnect_signal.connect(self.on_disconnect)
        self.browse_node_signal.connect(self.on_browse_node)
        self.read_node_signal.connect(self.on_read_node)
        self.write_node_signal.connect(self.on_write_node)
        self.read_attributes_signal.connect(self.on_read_attributes)
        self.read_references_signal.connect(self.on_read_references)
        self.subscribe_signal.connect(self.on_subscribe)
        self.unsubscribe_signal.connect(self.on_unsubscribe)
        self.register_node_signal.connect(self.on_register_node)
        self.unregister_node_signal.connect(self.on_unregister_node)
        self.start_livebit_signal.connect(self.on_start_livebit)
        self.stop_livebit_signal.connect(self.on_stop_livebit)
        self.save_registered_nodes_signal.connect(self.on_save_registered_nodes)
        self.load_registered_nodes_signal.connect(self.on_load_registered_nodes)
    
    @pyqtSlot(int)
    def on_tab_changed(self, index):
        """Handle tab change event
        
        Args:
            index: New tab index
        """
        # Save the current tab to config
        self.config.set("ui", "last_active_tab", index)
    
    @pyqtSlot(ConnectionStatus, str)
    def on_connection_status_changed(self, status, message):
        """Handle connection status change
        
        Args:
            status: New connection status
            message: Status message
        """
        # Update connection status in status bar
        if status == ConnectionStatus.CONNECTED:
            self.connection_status_label.setText("Connected")
            self.connection_status_label.setProperty("connectionStatus", "connected")
            self.disconnect_action.setEnabled(True)
        elif status == ConnectionStatus.DISCONNECTED:
            self.connection_status_label.setText("Disconnected")
            self.connection_status_label.setProperty("connectionStatus", "disconnected")
            self.disconnect_action.setEnabled(False)
            self.endpoint_label.setText("No Endpoint")
        elif status == ConnectionStatus.CONNECTING:
            self.connection_status_label.setText("Connecting...")
            self.connection_status_label.setProperty("connectionStatus", "connecting")
            self.disconnect_action.setEnabled(False)
        elif status == ConnectionStatus.ERROR:
            self.connection_status_label.setText("Error")
            self.connection_status_label.setProperty("connectionStatus", "error")
            self.disconnect_action.setEnabled(False)
        
        # Force style sheet update
        self.connection_status_label.style().unpolish(self.connection_status_label)
        self.connection_status_label.style().polish(self.connection_status_label)
        
        # Update status bar message
        self.status_bar.showMessage(message, 5000)
    
    @pyqtSlot()
    def on_connection_established(self):
        """Handle connection established event"""
        # Enable UI elements that require connection
        self.disconnect_action.setEnabled(True)
        
        # Update endpoint label
        self.endpoint_label.setText(self.client.endpoint_url)
    
    @pyqtSlot(str)
    def on_connection_lost(self, reason):
        """Handle connection lost event
        
        Args:
            reason: Reason for connection loss
        """
        # Show error message
        QMessageBox.warning(
            self,
            "Connection Lost",
            f"Connection to server lost: {reason}",
            QMessageBox.Ok
        )
    
    @pyqtSlot(str, str)
    def log_message(self, level, message):
        """Add message to log view
        
        Args:
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            message: Log message
        """
        # Set color based on log level
        color = "#FFFFFF"  # Default white
        if level == "DEBUG":
            color = "#808080"  # Gray
        elif level == "INFO":
            color = "#00FF00"  # Green
        elif level == "WARNING":
            color = "#FFFF00"  # Yellow
        elif level == "ERROR":
            color = "#FF0000"  # Red
        elif level == "CRITICAL":
            color = "#FF00FF"  # Magenta
        
        # Add formatted message to log view
        cursor = self.log_text.textCursor()
        cursor.movePosition(cursor.End)
        current_format = cursor.charFormat()
        
        format = current_format
        format.setForeground(Qt.GlobalColor(Qt.white))
        cursor.setCharFormat(format)
        cursor.insertText(f"[{level}] ")
        
        format.setForeground(Qt.GlobalColor(Qt.gray))
        cursor.setCharFormat(format)
        cursor.insertText(f"{message}\n")
        
        # Scroll to bottom
        self.log_text.verticalScrollBar().setValue(self.log_text.verticalScrollBar().maximum())
    
    def show_connect_dialog(self):
        """Show connect dialog"""
        dialog = ConnectionDialog(self.config, self)
        if dialog.exec_():
            # Get connection parameters
            endpoint = dialog.endpoint_edit.text()
            username = dialog.username_edit.text() if dialog.auth_group.isChecked() else None
            password = dialog.password_edit.text() if dialog.auth_group.isChecked() else None
            security_policy = dialog.security_combo.currentText()
            certificate = dialog.certificate_edit.text() if dialog.security_group.isChecked() else None
            private_key = dialog.private_key_edit.text() if dialog.security_group.isChecked() else None
            
            # Save to config (except password)
            self.config.set("connection", "endpoint", endpoint)
            if username:
                self.config.save_credentials(endpoint, username, password)
            
            if dialog.security_group.isChecked():
                self.config.set("connection", "security_policy", security_policy)
                self.config.set("connection", "certificate", certificate)
                self.config.set("connection", "private_key", private_key)
            
            # Update auto-reconnect settings
            self.config.set("connection", "auto_reconnect", dialog.auto_reconnect_check.isChecked())
            self.config.set("connection", "initial_delay", dialog.initial_delay_spin.value())
            self.config.set("connection", "max_delay", dialog.max_delay_spin.value())
            self.config.set("connection", "max_attempts", dialog.max_attempts_spin.value())
            
            # Initiate connection
            self.connect_signal.emit(endpoint, username, password, security_policy, certificate, private_key)
    
    def confirm_disconnect(self):
        """Confirm and disconnect from server"""
        reply = QMessageBox.question(
            self,
            "Confirm Disconnect",
            "Are you sure you want to disconnect from the server?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.disconnect_signal.emit()
    
    def show_certificate_manager(self):
        """Show certificate manager dialog"""
        # This will be implemented in a future version
        QMessageBox.information(
            self,
            "Certificate Manager",
            "Certificate Manager is not implemented yet.",
            QMessageBox.Ok
        )
    
    def show_about_dialog(self):
        """Show about dialog"""
        QMessageBox.about(
            self,
            "About OPC UA Client",
            "<h1>OPC UA Client</h1>"
            "<p>Version 1.0.0</p>"
            "<p>A modern OPC UA Client built with asyncua and PyQt5.</p>"
            "<p>Based on the <a href='https://github.com/FreeOpcUa/opcua-asyncio'>opcua-asyncio</a> library.</p>"
        )
    
    async def auto_connect(self):
        """Auto-connect to server"""
        try:
            logger.info("Auto-connecting to saved endpoint...")
            
            # Get connection parameters from config
            endpoint = self.config.get("connection", "endpoint")
            username = None
            password = None
            security_policy = self.config.get("connection", "security_policy")
            certificate = self.config.get("connection", "certificate")
            private_key = self.config.get("connection", "private_key")
            
            # Get credentials if saved
            if endpoint:
                # Try to find saved credentials
                try:
                    import keyring
                    service_id = f"opcua_client_{endpoint}"
                    # Get all user credentials for this endpoint
                    for user in keyring.get_credential(service_id, None) or []:
                        username = user
                        password = keyring.get_password(service_id, username)
                        break  # Just use the first one found
                except:
                    logger.warning("Failed to retrieve saved credentials")
            
            # Emit connect signal
            self.connect_signal.emit(endpoint, username, password, security_policy, certificate, private_key)
            
        except Exception as e:
            logger.error(f"Error during auto-connect: {e}")
    
    def closeEvent(self, event):
        """Handle window close event
        
        Args:
            event: Close event
        """
        # Save window geometry
        self._save_geometry()
        
        # Disconnect from server if connected
        if self.client.status == ConnectionStatus.CONNECTED:
            asyncio.create_task(self.client.disconnect())
        
        # Accept the event
        event.accept()
    
    #------ Async method wrappers ------#
    
    @pyqtSlot(str, str, str, str, str, str)
    def on_connect(self, endpoint, username, password, security_policy, certificate, private_key):
        """Connect to server (async wrapper)
        
        Args:
            endpoint: Server endpoint
            username: Username
            password: Password
            security_policy: Security policy
            certificate: Certificate file path
            private_key: Private key file path
        """
        # Set client properties
        self.client.auto_reconnect = self.config.get("connection", "auto_reconnect")
        self.client.initial_reconnect_delay = self.config.get("connection", "initial_delay")
        self.client.max_reconnect_delay = self.config.get("connection", "max_delay")
        self.client.max_reconnect_attempts = self.config.get("connection", "max_attempts")
        
        # Create async task
        asyncio.create_task(
            self.client.connect(
                endpoint, 
                username, 
                password, 
                security_policy,
                certificate, 
                private_key
            )
        )
    
    @pyqtSlot()
    def on_disconnect(self):
        """Disconnect from server (async wrapper)"""
        asyncio.create_task(self.client.disconnect())
    
    @pyqtSlot(object)
    def on_browse_node(self, node):
        """Browse node children (async wrapper)
        
        Args:
            node: Node to browse
        """
        asyncio.create_task(self.client.browse_node(node))
    
    @pyqtSlot(object)
    def on_read_node(self, node):
        """Read node value (async wrapper)
        
        Args:
            node: Node to read
        """
        asyncio.create_task(self.client.read_node_value(node))
    
    @pyqtSlot(object, object)
    def on_write_node(self, node, value):
        """Write value to node (async wrapper)
        
        Args:
            node: Node to write to
            value: Value to write
        """
        asyncio.create_task(self.client.write_node_value(node, value))
    
    @pyqtSlot(object)
    def on_read_attributes(self, node):
        """Read node attributes (async wrapper)
        
        Args:
            node: Node to read attributes from
        """
        asyncio.create_task(self.client.read_node_attributes(node))
    
    @pyqtSlot(object)
    def on_read_references(self, node):
        """Read node references (async wrapper)
        
        Args:
            node: Node to read references from
        """
        asyncio.create_task(self.client.read_node_references(node))
    
    @pyqtSlot(list, int, str)
    def on_subscribe(self, nodes, interval, subscription_id=None):
        """Create subscription (async wrapper)
        
        Args:
            nodes: List of nodes to subscribe to
            interval: Subscription interval
            subscription_id: Optional subscription ID
        """
        asyncio.create_task(self.client.create_subscription(nodes, interval, subscription_id))
    
    @pyqtSlot(str)
    def on_unsubscribe(self, subscription_id):
        """Remove subscription (async wrapper)
        
        Args:
            subscription_id: Subscription ID
        """
        asyncio.create_task(self.client.remove_subscription(subscription_id))
    
    @pyqtSlot(object, str)
    def on_register_node(self, node, node_name=None):
        """Register node (async wrapper)
        
        Args:
            node: Node to register
            node_name: Optional node name
        """
        asyncio.create_task(self.client.register_node(node, node_name))
    
    @pyqtSlot(str)
    def on_unregister_node(self, node_name):
        """Unregister node (async wrapper)
        
        Args:
            node_name: Name of node to unregister
        """
        asyncio.create_task(self.client.unregister_node(node_name))
    
    @pyqtSlot(str, int)
    def on_start_livebit(self, node_name, interval):
        """Start LiveBit functionality (async wrapper)
        
        Args:
            node_name: Node name
            interval: Toggle interval
        """
        asyncio.create_task(self.client.start_livebit(node_name, interval))
    
    @pyqtSlot(str)
    def on_stop_livebit(self, node_name):
        """Stop LiveBit functionality (async wrapper)
        
        Args:
            node_name: Node name
        """
        asyncio.create_task(self.client.stop_livebit(node_name))
    
    @pyqtSlot(str)
    def on_save_registered_nodes(self, directory):
        """Save registered nodes (async wrapper)
        
        Args:
            directory: Directory to save to
        """
        asyncio.create_task(self.client.save_registered_nodes(directory))
    
    @pyqtSlot(str)
    def on_load_registered_nodes(self, directory):
        """Load registered nodes (async wrapper)
        
        Args:
            directory: Directory to load from
        """
        asyncio.create_task(self.client.load_registered_nodes(directory))
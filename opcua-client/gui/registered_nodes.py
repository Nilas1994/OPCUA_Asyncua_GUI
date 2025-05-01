#!/usr/bin/env python3
"""
Registered nodes widget for OPC UA Client
"""
import logging
from typing import Dict, List, Optional, Any

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QToolBar, QAction, QHeaderView, QAbstractItemView,
    QMessageBox, QInputDialog, QMenu, QCheckBox, QSpinBox, QLabel,
    QFormLayout, QGroupBox
)
from PyQt5.QtCore import Qt, pyqtSlot, pyqtSignal
from PyQt5.QtGui import QIcon

from asyncua import ua

logger = logging.getLogger(__name__)


class RegisteredNodesWidget(QWidget):
    """Widget for managing registered nodes"""
    
    def __init__(self, client):
        """Initialize widget
        
        Args:
            client: OPC UA client instance
        """
        super().__init__()
        self.client = client
        
        # Set up UI
        self.layout = QVBoxLayout(self)
        
        # Create toolbar
        self.toolbar = QToolBar("Registered Nodes Toolbar")
        self.layout.addWidget(self.toolbar)
        
        # Add refresh action
        self.refresh_action = QAction("Refresh", self)
        self.refresh_action.setIcon(QIcon.fromTheme("view-refresh"))
        self.refresh_action.triggered.connect(self.refresh_values)
        self.toolbar.addAction(self.refresh_action)
        
        # Add unregister action
        self.unregister_action = QAction("Unregister", self)
        self.unregister_action.setIcon(QIcon.fromTheme("list-remove"))
        self.unregister_action.triggered.connect(self.unregister_selected)
        self.toolbar.addAction(self.unregister_action)
        
        # Add toggle LiveBit action
        self.livebit_action = QAction("Toggle LiveBit", self)
        self.livebit_action.setIcon(QIcon.fromTheme("media-playback-start"))
        self.livebit_action.triggered.connect(self.toggle_livebit)
        self.toolbar.addAction(self.livebit_action)
        
        # Create LiveBit configuration group
        self.livebit_group = QGroupBox("LiveBit Configuration")
        livebit_layout = QFormLayout(self.livebit_group)
        
        self.livebit_interval_spin = QSpinBox()
        self.livebit_interval_spin.setRange(1, 60)
        self.livebit_interval_spin.setValue(5)
        self.livebit_interval_spin.setSuffix(" seconds")
        livebit_layout.addRow("Toggle Interval:", self.livebit_interval_spin)
        
        # Add LiveBit group to layout
        self.layout.addWidget(self.livebit_group)
        
        # Create table for registered nodes
        self.nodes_table = QTableWidget()
        self.nodes_table.setColumnCount(5)
        self.nodes_table.setHorizontalHeaderLabels(["Name", "Node ID", "Value", "Timestamp", "Actions"])
        self.nodes_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.nodes_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.nodes_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.nodes_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.nodes_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.nodes_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.nodes_table.setEditTriggers(QAbstractItemView.DoubleClicked)
        self.nodes_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.nodes_table.customContextMenuRequested.connect(self.show_context_menu)
        self.nodes_table.cellChanged.connect(self.on_cell_changed)
        
        self.layout.addWidget(self.nodes_table)
        
        # Store active LiveBit nodes
        self.livebit_active = set()
        
        # Connect signals
        self.client.registered_node_added.connect(self.on_node_registered)
        self.client.registered_node_removed.connect(self.on_node_unregistered)
        self.client.node_read_complete.connect(self.on_node_read_complete)
        self.client.connection_established.connect(self.on_connection_established)
        self.client.connection_status_changed.connect(self.on_connection_status_changed)
    
    def on_connection_established(self):
        """Handle connection established event"""
        # Clear the table
        self.nodes_table.setRowCount(0)
        self.livebit_active.clear()
    
    def on_connection_status_changed(self, status, message):
        """Handle connection status change
        
        Args:
            status: New connection status
            message: Status message
        """
        # Enable/disable controls based on connection status
        from client import ConnectionStatus
        enabled = (status == ConnectionStatus.CONNECTED)
        
        self.refresh_action.setEnabled(enabled)
        self.unregister_action.setEnabled(enabled)
        self.livebit_action.setEnabled(enabled)
        self.nodes_table.setEnabled(enabled)
    
    def on_node_registered(self, node_name, node):
        """Handle node registered event
        
        Args:
            node_name: Node name
            node: Node object
        """
        # Add node to table
        row = self.nodes_table.rowCount()
        self.nodes_table.insertRow(row)
        
        # Set node name
        self.nodes_table.setItem(row, 0, QTableWidgetItem(node_name))
        
        # Set node ID
        try:
            node_id = self.client.registered_node_ids[node_name]
            self.nodes_table.setItem(row, 1, QTableWidgetItem(str(node_id)))
        except:
            self.nodes_table.setItem(row, 1, QTableWidgetItem("Unknown"))
            
        # Set value and timestamp columns
        self.nodes_table.setItem(row, 2, QTableWidgetItem(""))
        self.nodes_table.setItem(row, 3, QTableWidgetItem(""))
        
        # Add action buttons
        actions_widget = QWidget()
        actions_layout = QHBoxLayout(actions_widget)
        actions_layout.setContentsMargins(0, 0, 0, 0)
        
        # Read button
        read_button = QPushButton("Read")
        read_button.clicked.connect(lambda: self.read_node(node_name))
        actions_layout.addWidget(read_button)
        
        # Write button
        write_button = QPushButton("Write")
        write_button.clicked.connect(lambda: self.write_node(node_name))
        actions_layout.addWidget(write_button)
        
        # Add actions widget to table
        self.nodes_table.setCellWidget(row, 4, actions_widget)
        
        # Read node value
        self.read_node(node_name)
    
    def on_node_unregistered(self, node_name):
        """Handle node unregistered event
        
        Args:
            node_name: Node name
        """
        # Remove node from table
        for row in range(self.nodes_table.rowCount()):
            if self.nodes_table.item(row, 0).text() == node_name:
                self.nodes_table.removeRow(row)
                break
        
        # Remove from LiveBit active set
        self.livebit_active.discard(node_name)
    
    def on_node_read_complete(self, node, value):
        """Handle node read complete event
        
        Args:
            node: Node object
            value: Node value
        """
        # Find node in registered nodes
        node_name = None
        for name, n in self.client.registered_nodes.items():
            if n == node:
                node_name = name
                break
                
        if not node_name:
            return
            
        # Update value in table
        for row in range(self.nodes_table.rowCount()):
            if self.nodes_table.item(row, 0).text() == node_name:
                # Update value
                if value and value.Value and value.Value.Value is not None:
                    self.nodes_table.item(row, 2).setText(str(value.Value.Value))
                else:
                    self.nodes_table.item(row, 2).setText("")
                    
                # Update timestamp
                if value and value.SourceTimestamp:
                    self.nodes_table.item(row, 3).setText(str(value.SourceTimestamp))
                else:
                    self.nodes_table.item(row, 3).setText("")
                    
                break
    
    def read_node(self, node_name):
        """Read value of registered node
        
        Args:
            node_name: Node name
        """
        if node_name in self.client.registered_nodes:
            self.client.read_node_signal.emit(self.client.registered_nodes[node_name])
    
    def write_node(self, node_name):
        """Write value to registered node
        
        Args:
            node_name: Node name
        """
        if node_name not in self.client.registered_nodes:
            return
            
        # Find node in table
        for row in range(self.nodes_table.rowCount()):
            if self.nodes_table.item(row, 0).text() == node_name:
                # Get current value
                value_str = self.nodes_table.item(row, 2).text()
                
                # Ask for new value
                new_value, ok = QInputDialog.getText(
                    self,
                    "Write Value",
                    f"Enter new value for node '{node_name}':",
                    text=value_str
                )
                
                if ok:
                    # Try to convert value appropriately based on current value type
                    try:
                        node = self.client.registered_nodes[node_name]
                        
                        # Get the node data type
                        data_type = None
                        try:
                            attributes = self.client.read_node_attributes(node)
                            if "DataType" in attributes:
                                data_type = attributes["DataType"]
                        except:
                            pass
                            
                        # Convert based on current value or guess
                        if value_str.lower() in ("true", "false"):
                            # Boolean
                            converted_value = new_value.lower() in ("true", "1", "yes", "y")
                        elif value_str.isdigit():
                            # Integer
                            converted_value = int(new_value)
                        elif value_str.replace(".", "", 1).isdigit():
                            # Float
                            converted_value = float(new_value)
                        else:
                            # String
                            converted_value = new_value
                            
                        # Write to node
                        self.client.write_node_signal.emit(node, converted_value)
                        
                        # Read back the value
                        self.client.read_node_signal.emit(node)
                        
                    except Exception as e:
                        QMessageBox.warning(
                            self,
                            "Write Error",
                            f"Error writing value: {e}",
                            QMessageBox.Ok
                        )
                        
                break
    
    def refresh_values(self):
        """Refresh values of all registered nodes"""
        for node_name, node in self.client.registered_nodes.items():
            self.client.read_node_signal.emit(node)
    
    def unregister_selected(self):
        """Unregister selected nodes"""
        selected_rows = set()
        for item in self.nodes_table.selectedItems():
            selected_rows.add(item.row())
            
        if not selected_rows:
            QMessageBox.warning(
                self,
                "Unregister Nodes",
                "No nodes selected",
                QMessageBox.Ok
            )
            return
            
        # Confirm unregistration
        node_count = len(selected_rows)
        reply = QMessageBox.question(
            self,
            "Unregister Nodes",
            f"Unregister {node_count} selected node(s)?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Get node names to unregister
            node_names = []
            for row in sorted(selected_rows, reverse=True):
                node_names.append(self.nodes_table.item(row, 0).text())
                
            # Unregister nodes
            for name in node_names:
                self.client.unregister_node_signal.emit(name)
    
    def toggle_livebit(self):
        """Toggle LiveBit functionality for selected nodes"""
        # Get selected nodes
        selected_rows = set()
        for item in self.nodes_table.selectedItems():
            selected_rows.add(item.row())
            
        if not selected_rows:
            QMessageBox.warning(
                self,
                "Toggle LiveBit",
                "No nodes selected",
                QMessageBox.Ok
            )
            return
            
        # Get node names
        node_names = []
        for row in sorted(selected_rows):
            node_names.append(self.nodes_table.item(row, 0).text())
            
        # Toggle LiveBit for each node
        for name in node_names:
            if name in self.livebit_active:
                # Stop LiveBit
                self.client.stop_livebit_signal.emit(name)
                self.livebit_active.discard(name)
            else:
                # Start LiveBit
                interval = self.livebit_interval_spin.value()
                self.client.start_livebit_signal.emit(name, interval)
                self.livebit_active.add(name)
    
    def on_cell_changed(self, row, col):
        """Handle cell edit
        
        Args:
            row: Row index
            col: Column index
        """
        # Only handle value column (2)
        if col != 2:
            return
            
        # Get node name and new value
        node_name = self.nodes_table.item(row, 0).text()
        new_value = self.nodes_table.item(row, 2).text()
        
        if node_name not in self.client.registered_nodes:
            return
            
        try:
            # Convert value (simplified - assumes string values)
            node = self.client.registered_nodes[node_name]
            
            # Try to convert to appropriate type
            if new_value.lower() in ("true", "false"):
                # Boolean
                converted_value = new_value.lower() == "true"
            elif new_value.isdigit():
                # Integer
                converted_value = int(new_value)
            elif new_value.replace(".", "", 1).isdigit():
                # Float
                converted_value = float(new_value)
            else:
                # String
                converted_value = new_value
                
            # Write to node
            self.client.write_node_signal.emit(node, converted_value)
            
            # Read back the value
            self.client.read_node_signal.emit(node)
            
        except Exception as e:
            QMessageBox.warning(
                self,
                "Write Error",
                f"Error writing value: {e}",
                QMessageBox.Ok
            )
    
    def show_context_menu(self, pos):
        """Show context menu for table
        
        Args:
            pos: Position
        """
        # Get row at position
        row = self.nodes_table.rowAt(pos.y())
        if row < 0:
            return
            
        # Select the row
        self.nodes_table.selectRow(row)
        
        # Get node name
        node_name = self.nodes_table.item(row, 0).text()
        
        # Create context menu
        menu = QMenu(self)
        
        # Add actions
        read_action = menu.addAction("Read Value")
        read_action.triggered.connect(lambda: self.read_node(node_name))
        
        write_action = menu.addAction("Write Value")
        write_action.triggered.connect(lambda: self.write_node(node_name))
        
        menu.addSeparator()
        
        if node_name in self.livebit_active:
            livebit_action = menu.addAction("Stop LiveBit")
            livebit_action.triggered.connect(
                lambda: self.client.stop_livebit_signal.emit(node_name) or self.livebit_active.discard(node_name)
            )
        else:
            livebit_action = menu.addAction("Start LiveBit")
            livebit_action.triggered.connect(
                lambda: self.client.start_livebit_signal.emit(node_name, self.livebit_interval_spin.value()) or self.livebit_active.add(node_name)
            )
            
        menu.addSeparator()
        
        unregister_action = menu.addAction("Unregister")
        unregister_action.triggered.connect(lambda: self.client.unregister_node_signal.emit(node_name))
        
        # Show menu
        menu.exec_(self.nodes_table.viewport().mapToGlobal(pos))
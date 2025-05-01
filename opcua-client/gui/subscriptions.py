#!/usr/bin/env python3
"""
Subscriptions widget for OPC UA Client
"""
import logging
from typing import Dict, List, Optional, Any
import json
from datetime import datetime

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QToolBar, QAction, QHeaderView, QAbstractItemView,
    QMessageBox, QInputDialog, QMenu, QSpinBox, QLabel, QFormLayout,
    QGroupBox
)
from PyQt5.QtCore import Qt, pyqtSlot, pyqtSignal
from PyQt5.QtGui import QIcon

from asyncua import ua
from asyncua.common.subscription import Subscription

logger = logging.getLogger(__name__)


class SubscriptionsWidget(QWidget):
    """Widget for managing OPC UA subscriptions"""
    
    def __init__(self, client):
        """Initialize widget
        
        Args:
            client: OPC UA client instance
        """
        super().__init__()
        self.client = client
        
        # Set up UI
        self.layout = QVBoxLayout(self)
        
        # Create subscription configuration group
        self.config_group = QGroupBox("Subscription Configuration")
        config_layout = QFormLayout(self.config_group)
        
        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(100, 60000)
        self.interval_spin.setValue(1000)
        self.interval_spin.setSuffix(" ms")
        config_layout.addRow("Publishing Interval:", self.interval_spin)
        
        # Add configuration group to layout
        self.layout.addWidget(self.config_group)
        
        # Create toolbar
        self.toolbar = QToolBar("Subscriptions Toolbar")
        self.layout.addWidget(self.toolbar)
        
        # Add unsubscribe action
        self.unsubscribe_action = QAction("Unsubscribe Selected", self)
        self.unsubscribe_action.setIcon(QIcon.fromTheme("list-remove"))
        self.unsubscribe_action.triggered.connect(self.unsubscribe_selected)
        self.toolbar.addAction(self.unsubscribe_action)
        
        # Add unsubscribe all action
        self.unsubscribe_all_action = QAction("Unsubscribe All", self)
        self.unsubscribe_all_action.setIcon(QIcon.fromTheme("edit-clear"))
        self.unsubscribe_all_action.triggered.connect(self.unsubscribe_all)
        self.toolbar.addAction(self.unsubscribe_all_action)
        
        # Add save to file action
        self.save_action = QAction("Save Data", self)
        self.save_action.setIcon(QIcon.fromTheme("document-save"))
        self.save_action.triggered.connect(self.save_subscription_data)
        self.toolbar.addAction(self.save_action)
        
        # Create table for subscriptions
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Subscription ID", "Node ID", "Value", "Timestamp", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        
        self.layout.addWidget(self.table)
        
        # Connect signals
        self.client.subscription_created.connect(self.on_subscription_created)
        self.client.subscription_data_change.connect(self.on_subscription_data_change)
        self.client.subscription_event.connect(self.on_subscription_event)
        self.client.connection_status_changed.connect(self.on_connection_status_changed)
        
        # Store subscription data
        self.subscription_data = {}
    
    def on_connection_status_changed(self, status, message):
        """Handle connection status change
        
        Args:
            status: New connection status
            message: Status message
        """
        # Enable/disable controls based on connection status
        from client import ConnectionStatus
        enabled = (status == ConnectionStatus.CONNECTED)
        
        self.unsubscribe_action.setEnabled(enabled)
        self.unsubscribe_all_action.setEnabled(enabled)
        self.save_action.setEnabled(enabled)
        self.table.setEnabled(enabled)
        
        # Clear subscriptions if disconnected
        if status == ConnectionStatus.DISCONNECTED:
            self.table.setRowCount(0)
            self.subscription_data.clear()
    
    def on_subscription_created(self, subscription_id, subscription):
        """Handle subscription created event
        
        Args:
            subscription_id: Subscription ID
            subscription: Subscription object
        """
        logger.info(f"Subscription created: {subscription_id}")
        
        # The node information will be added when the first data change notification arrives
        
        # Initialize subscription data
        self.subscription_data[subscription_id] = {
            "nodes": {},
            "values": {}
        }
    
    def on_subscription_data_change(self, subscription_id, node, value, data):
        """Handle subscription data change event
        
        Args:
            subscription_id: Subscription ID
            node: Node object
            value: Node value
            data: Data object
        """
        # Store node if not already present
        try:
            node_id = self.client.client.get_node(node).nodeid
            node_id_str = str(node_id)
            
            if node_id_str not in self.subscription_data[subscription_id]["nodes"]:
                self.subscription_data[subscription_id]["nodes"][node_id_str] = node
                
                # Add row to table
                row = self.table.rowCount()
                self.table.insertRow(row)
                
                self.table.setItem(row, 0, QTableWidgetItem(subscription_id))
                self.table.setItem(row, 1, QTableWidgetItem(node_id_str))
                self.table.setItem(row, 2, QTableWidgetItem(""))
                self.table.setItem(row, 3, QTableWidgetItem(""))
                self.table.setItem(row, 4, QTableWidgetItem("Active"))
                
            # Store value
            self.subscription_data[subscription_id]["values"][node_id_str] = {
                "value": value,
                "data": data,
                "timestamp": datetime.now().isoformat()
            }
            
            # Update table with new value
            for row in range(self.table.rowCount()):
                if (self.table.item(row, 0).text() == subscription_id and
                    self.table.item(row, 1).text() == node_id_str):
                    
                    # Update value
                    self.table.item(row, 2).setText(str(value))
                    
                    # Update timestamp
                    if data and data.SourceTimestamp:
                        self.table.item(row, 3).setText(str(data.SourceTimestamp))
                    else:
                        self.table.item(row, 3).setText(datetime.now().isoformat())
                        
                    break
                    
        except Exception as e:
            logger.error(f"Error handling subscription data change: {e}")
    
    def on_subscription_event(self, subscription_id, event):
        """Handle subscription event
        
        Args:
            subscription_id: Subscription ID
            event: Event object
        """
        # Log the event
        logger.info(f"Subscription {subscription_id} event: {event}")
    
    def unsubscribe_selected(self):
        """Unsubscribe from selected subscriptions"""
        selected_rows = set()
        for item in self.table.selectedItems():
            selected_rows.add(item.row())
            
        if not selected_rows:
            QMessageBox.warning(
                self,
                "Unsubscribe",
                "No subscriptions selected",
                QMessageBox.Ok
            )
            return
            
        # Group by subscription ID
        subscription_ids = set()
        for row in selected_rows:
            subscription_ids.add(self.table.item(row, 0).text())
            
        # Confirm unsubscribe
        count = len(subscription_ids)
        reply = QMessageBox.question(
            self,
            "Unsubscribe",
            f"Unsubscribe from {count} subscription(s)?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Unsubscribe from each subscription
            for sub_id in subscription_ids:
                self.client.unsubscribe_signal.emit(sub_id)
                
            # Remove rows from table
            for row in sorted(selected_rows, reverse=True):
                self.table.removeRow(row)
                
            # Remove from subscription data
            for sub_id in subscription_ids:
                self.subscription_data.pop(sub_id, None)
    
    def unsubscribe_all(self):
        """Unsubscribe from all subscriptions"""
        if self.table.rowCount() == 0:
            QMessageBox.information(
                self,
                "Unsubscribe All",
                "No active subscriptions",
                QMessageBox.Ok
            )
            return
            
        # Confirm unsubscribe
        count = len(self.subscription_data)
        reply = QMessageBox.question(
            self,
            "Unsubscribe All",
            f"Unsubscribe from all {count} subscription(s)?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Unsubscribe from each subscription
            for sub_id in list(self.subscription_data.keys()):
                self.client.unsubscribe_signal.emit(sub_id)
                
            # Clear table
            self.table.setRowCount(0)
            
            # Clear subscription data
            self.subscription_data.clear()
    
    def save_subscription_data(self):
        """Save subscription data to file"""
        from PyQt5.QtWidgets import QFileDialog
        
        if not self.subscription_data:
            QMessageBox.warning(
                self,
                "Save Data",
                "No subscription data to save",
                QMessageBox.Ok
            )
            return
            
        # Ask for file name
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Subscription Data",
            "",
            "JSON Files (*.json);;All Files (*)"
        )
        
        if not file_path:
            return
            
        try:
            # Format data for JSON serialization
            data = {}
            for sub_id, sub_data in self.subscription_data.items():
                data[sub_id] = {
                    "nodes": {},
                    "values": {}
                }
                
                # Add node information
                for node_id, node in sub_data["nodes"].items():
                    data[sub_id]["nodes"][node_id] = str(node)
                    
                # Add value information
                for node_id, value_data in sub_data["values"].items():
                    data[sub_id]["values"][node_id] = {
                        "value": str(value_data["value"]),
                        "timestamp": value_data["timestamp"]
                    }
            
            # Write to file
            with open(file_path, "w") as f:
                json.dump(data, f, indent=4)
                
            QMessageBox.information(
                self,
                "Save Data",
                f"Subscription data saved to {file_path}",
                QMessageBox.Ok
            )
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "Save Error",
                f"Error saving subscription data: {e}",
                QMessageBox.Ok
            )
    
    def show_context_menu(self, pos):
        """Show context menu for table
        
        Args:
            pos: Position
        """
        # Get row at position
        row = self.table.rowAt(pos.y())
        if row < 0:
            return
            
        # Select the row
        self.table.selectRow(row)
        
        # Get subscription ID
        subscription_id = self.table.item(row, 0).text()
        
        # Create context menu
        menu = QMenu(self)
        
        # Add unsubscribe action
        unsubscribe_action = menu.addAction("Unsubscribe")
        unsubscribe_action.triggered.connect(
            lambda: self.client.unsubscribe_signal.emit(subscription_id) or self.table.removeRow(row)
        )
        
        # Add register action to register this node
        node_id_str = self.table.item(row, 1).text()
        if subscription_id in self.subscription_data and node_id_str in self.subscription_data[subscription_id]["nodes"]:
            node = self.subscription_data[subscription_id]["nodes"][node_id_str]
            
            register_action = menu.addAction("Register Node")
            register_action.triggered.connect(
                lambda: self.register_node(node)
            )
        
        # Show menu
        menu.exec_(self.table.viewport().mapToGlobal(pos))
    
    def register_node(self, node):
        """Register node
        
        Args:
            node: Node to register
        """
        # Ask for node name
        node_name, ok = QInputDialog.getText(
            self,
            "Register Node",
            "Enter name for registered node:",
            text=str(node.nodeid)
        )
        
        if ok and node_name:
            self.client.register_node_signal.emit(node, node_name)
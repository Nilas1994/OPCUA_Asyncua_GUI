#!/usr/bin/env python3
"""
Output widget for OPC UA Client
"""
import logging
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
import asyncio

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QToolBar, QAction, QHeaderView, QAbstractItemView,
    QMessageBox, QInputDialog, QMenu, QGroupBox, QFormLayout, QLabel,
    QComboBox, QCheckBox, QFileDialog, QSpinBox, QTextEdit, QSplitter
)
from PyQt5.QtCore import Qt, pyqtSlot, pyqtSignal, QTimer
from PyQt5.QtGui import QIcon

from asyncua import ua

logger = logging.getLogger(__name__)


class OutputWidget(QWidget):
    """Widget for data output from OPC UA Client"""
    
    def __init__(self, client):
        """Initialize widget
        
        Args:
            client: OPC UA client instance
        """
        super().__init__()
        self.client = client
        
        # Set up UI
        self.layout = QVBoxLayout(self)
        
        # Create configuration group
        self.config_group = QGroupBox("Output Configuration")
        config_layout = QFormLayout(self.config_group)
        
        # Output format
        self.format_combo = QComboBox()
        self.format_combo.addItems(["JSON", "CSV", "Text"])
        config_layout.addRow("Output Format:", self.format_combo)
        
        # Output directory
        self.output_dir_layout = QHBoxLayout()
        self.output_dir_edit = QLabel()
        self.output_dir_edit.setText(str(Path.home() / ".opcua_client" / "output"))
        self.output_dir_button = QPushButton("Browse...")
        self.output_dir_button.clicked.connect(self.browse_output_dir)
        self.output_dir_layout.addWidget(self.output_dir_edit)
        self.output_dir_layout.addWidget(self.output_dir_button)
        config_layout.addRow("Output Directory:", self.output_dir_layout)
        
        # Auto export
        self.auto_export_check = QCheckBox("Enable automatic export")
        self.auto_export_check.setChecked(False)
        self.auto_export_check.stateChanged.connect(self.toggle_auto_export)
        config_layout.addRow(self.auto_export_check)
        
        # Export interval
        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(1, 3600)
        self.interval_spin.setValue(60)
        self.interval_spin.setSuffix(" seconds")
        config_layout.addRow("Export Interval:", self.interval_spin)
        
        # Add configuration group to layout
        self.layout.addWidget(self.config_group)
        
        # Create toolbar
        self.toolbar = QToolBar("Output Toolbar")
        self.layout.addWidget(self.toolbar)
        
        # Add export now action
        self.export_action = QAction("Export Now", self)
        self.export_action.setIcon(QIcon.fromTheme("document-save"))
        self.export_action.triggered.connect(self.export_data)
        self.toolbar.addAction(self.export_action)
        
        # Add clear data action
        self.clear_action = QAction("Clear Data", self)
        self.clear_action.setIcon(QIcon.fromTheme("edit-clear"))
        self.clear_action.triggered.connect(self.clear_data)
        self.toolbar.addAction(self.clear_action)
        
        # Create splitter for table and preview
        self.splitter = QSplitter(Qt.Vertical)
        self.layout.addWidget(self.splitter, 1)
        
        # Create table for data
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Node Name", "Node ID", "Value", "Timestamp"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        
        self.splitter.addWidget(self.table)
        
        # Create preview text edit
        self.preview_text = QTextEdit()
        self.preview_text.setReadOnly(True)
        self.preview_text.setLineWrapMode(QTextEdit.NoWrap)
        
        self.splitter.addWidget(self.preview_text)
        
        # Set splitter sizes
        self.splitter.setSizes([600, 400])
        
        # Connect signals
        self.client.subscription_data_change.connect(self.on_subscription_data_change)
        self.client.connection_status_changed.connect(self.on_connection_status_changed)
        
        # Initialize export timer
        self.export_timer = QTimer()
        self.export_timer.timeout.connect(self.export_data)
        
        # Store data
        self.output_data = {}
        
        # Create output directory
        output_dir = Path(self.output_dir_edit.text())
        output_dir.mkdir(parents=True, exist_ok=True)
    
    def on_connection_status_changed(self, status, message):
        """Handle connection status change
        
        Args:
            status: New connection status
            message: Status message
        """
        # Enable/disable controls based on connection status
        from client import ConnectionStatus
        enabled = (status == ConnectionStatus.CONNECTED)
        
        self.export_action.setEnabled(enabled)
        self.auto_export_check.setEnabled(enabled)
        
        # Stop export timer if disconnected
        if status == ConnectionStatus.DISCONNECTED and self.auto_export_check.isChecked():
            self.auto_export_check.setChecked(False)
    
    def on_subscription_data_change(self, subscription_id, node, value, data):
        """Handle subscription data change event
        
        Args:
            subscription_id: Subscription ID
            node: Node object
            value: Node value
            data: Data object
        """
        try:
            # Get node details
            node_id = self.client.client.get_node(node).nodeid
            node_id_str = str(node_id)
            browse_name = asyncio.run_coroutine_threadsafe(
                node.read_browse_name(), asyncio.get_event_loop()).result()
            node_name = browse_name.Name
            
            # Update output data
            self.output_data[node_id_str] = {
                "node_name": node_name,
                "node_id": node_id_str,
                "value": str(value),
                "timestamp": datetime.now().isoformat()
            }
            
            # Update table
            # Check if node already exists in table
            found = False
            for row in range(self.table.rowCount()):
                if self.table.item(row, 1).text() == node_id_str:
                    # Update existing row
                    self.table.item(row, 2).setText(str(value))
                    self.table.item(row, 3).setText(datetime.now().isoformat())
                    found = True
                    break
                    
            if not found:
                # Add new row
                row = self.table.rowCount()
                self.table.insertRow(row)
                self.table.setItem(row, 0, QTableWidgetItem(node_name))
                self.table.setItem(row, 1, QTableWidgetItem(node_id_str))
                self.table.setItem(row, 2, QTableWidgetItem(str(value)))
                self.table.setItem(row, 3, QTableWidgetItem(datetime.now().isoformat()))
                
            # Update preview
            self.update_preview()
            
        except Exception as e:
            logger.error(f"Error handling subscription data change for output: {e}")
    
    def browse_output_dir(self):
        """Browse for output directory"""
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Output Directory",
            self.output_dir_edit.text()
        )
        
        if directory:
            self.output_dir_edit.setText(directory)
            
            # Create directory if it doesn't exist
            output_dir = Path(directory)
            output_dir.mkdir(parents=True, exist_ok=True)
    
    def toggle_auto_export(self, state):
        """Toggle automatic export
        
        Args:
            state: Checkbox state
        """
        if state == Qt.Checked:
            # Start timer
            interval_ms = self.interval_spin.value() * 1000
            self.export_timer.start(interval_ms)
            logger.info(f"Auto-export enabled with interval {self.interval_spin.value()} seconds")
        else:
            # Stop timer
            self.export_timer.stop()
            logger.info("Auto-export disabled")
    
    def export_data(self):
        """Export data to file"""
        if not self.output_data:
            QMessageBox.warning(
                self,
                "Export Data",
                "No data to export",
                QMessageBox.Ok
            )
            return
            
        try:
            # Get output directory
            output_dir = Path(self.output_dir_edit.text())
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate timestamp for filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Get output format
            output_format = self.format_combo.currentText().lower()
            
            # Generate filename
            filename = f"opcua_data_{timestamp}.{output_format}"
            file_path = output_dir / filename
            
            # Export based on format
            if output_format == "json":
                self.export_json(file_path)
            elif output_format == "csv":
                self.export_csv(file_path)
            elif output_format == "text":
                self.export_text(file_path)
                
            logger.info(f"Data exported to {file_path}")
            
            # Show message if not auto-export
            if not self.auto_export_check.isChecked():
                QMessageBox.information(
                    self,
                    "Export Data",
                    f"Data exported to {file_path}",
                    QMessageBox.Ok
                )
                
        except Exception as e:
            error_msg = f"Error exporting data: {e}"
            logger.error(error_msg)
            
            # Show error message if not auto-export
            if not self.auto_export_check.isChecked():
                QMessageBox.critical(
                    self,
                    "Export Error",
                    error_msg,
                    QMessageBox.Ok
                )
    
    def export_json(self, file_path):
        """Export data to JSON file
        
        Args:
            file_path: Path to output file
        """
        with open(file_path, "w") as f:
            json.dump(self.output_data, f, indent=4)
    
    def export_csv(self, file_path):
        """Export data to CSV file
        
        Args:
            file_path: Path to output file
        """
        import csv
        
        with open(file_path, "w", newline="") as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow(["NodeName", "NodeID", "Value", "Timestamp"])
            
            # Write data
            for node_id, data in self.output_data.items():
                writer.writerow([
                    data["node_name"],
                    data["node_id"],
                    data["value"],
                    data["timestamp"]
                ])
    
    def export_text(self, file_path):
        """Export data to text file
        
        Args:
            file_path: Path to output file
        """
        with open(file_path, "w") as f:
            f.write("OPC UA Client Data Export\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n\n")
            
            # Write data
            for node_id, data in self.output_data.items():
                f.write(f"Node Name: {data['node_name']}\n")
                f.write(f"Node ID: {data['node_id']}\n")
                f.write(f"Value: {data['value']}\n")
                f.write(f"Timestamp: {data['timestamp']}\n")
                f.write("-" * 50 + "\n")
    
    def clear_data(self):
        """Clear output data"""
        if not self.output_data:
            return
            
        reply = QMessageBox.question(
            self,
            "Clear Data",
            "Are you sure you want to clear all output data?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.output_data.clear()
            self.table.setRowCount(0)
            self.update_preview()
    
    def update_preview(self):
        """Update the preview text edit with current data format"""
        if not self.output_data:
            self.preview_text.clear()
            return
            
        # Get output format
        output_format = self.format_combo.currentText().lower()
        
        if output_format == "json":
            # JSON preview
            self.preview_text.setPlainText(json.dumps(self.output_data, indent=4))
        elif output_format == "csv":
            # CSV preview
            text = "NodeName,NodeID,Value,Timestamp\n"
            for node_id, data in self.output_data.items():
                text += f"{data['node_name']},{data['node_id']},{data['value']},{data['timestamp']}\n"
            self.preview_text.setPlainText(text)
        elif output_format == "text":
            # Text preview
            text = "OPC UA Client Data Export\n"
            text += f"Timestamp: {datetime.now().isoformat()}\n\n"
            
            for node_id, data in self.output_data.items():
                text += f"Node Name: {data['node_name']}\n"
                text += f"Node ID: {data['node_id']}\n"
                text += f"Value: {data['value']}\n"
                text += f"Timestamp: {data['timestamp']}\n"
                text += "-" * 50 + "\n"
                
            self.preview_text.setPlainText(text)
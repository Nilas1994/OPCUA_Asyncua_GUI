#!/usr/bin/env python3
"""
Browser widget for OPC UA Client
"""
import asyncio
import logging
from typing import Optional, Dict, List, Any, Union

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTreeView, QTableWidget, 
    QTableWidgetItem, QSplitter, QAbstractItemView, QHeaderView,
    QTabWidget, QToolBar, QAction, QPushButton, QMenu, QMessageBox,
    QInputDialog, QLineEdit, QComboBox, QLabel
)
from PyQt5.QtCore import Qt, QModelIndex, pyqtSlot, pyqtSignal
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QIcon

from asyncua import ua
from asyncua.common.node import Node

logger = logging.getLogger(__name__)


class OpcUaTreeItem(QStandardItem):
    """Tree item for OPC UA nodes"""
    
    def __init__(self, text: str, node: Node):
        """Initialize tree item
        
        Args:
            text: Display text
            node: OPC UA node
        """
        super().__init__(text)
        self.node = node
        self.node_id = None
        self.node_class = None
        self.is_loaded = False
        self.setEditable(False)
        
        # Set placeholder item to show expand button
        self.appendRow(QStandardItem("Loading..."))
    
    def set_node_details(self, node_id: ua.NodeId, node_class: ua.NodeClass):
        """Set node details
        
        Args:
            node_id: Node ID
            node_class: Node class
        """
        self.node_id = node_id
        self.node_class = node_class
        
        # Set icon based on node class
        if node_class == ua.NodeClass.Object:
            self.setIcon(QIcon.fromTheme("folder"))
        elif node_class == ua.NodeClass.Variable:
            self.setIcon(QIcon.fromTheme("text-x-generic"))
        elif node_class == ua.NodeClass.Method:
            self.setIcon(QIcon.fromTheme("system-run"))
        elif node_class == ua.NodeClass.ObjectType:
            self.setIcon(QIcon.fromTheme("dialog-information"))
        elif node_class == ua.NodeClass.VariableType:
            self.setIcon(QIcon.fromTheme("dialog-information"))
        elif node_class == ua.NodeClass.ReferenceType:
            self.setIcon(QIcon.fromTheme("emblem-symbolic-link"))
        elif node_class == ua.NodeClass.DataType:
            self.setIcon(QIcon.fromTheme("text-x-script"))
        elif node_class == ua.NodeClass.View:
            self.setIcon(QIcon.fromTheme("view-list"))
    
    def type(self) -> int:
        """Get item type
        
        Returns:
            Item type (QStandardItem.UserType + 1)
        """
        return QStandardItem.UserType + 1


class BrowserWidget(QWidget):
    """Browser widget for OPC UA nodes"""
    
    # Define signal for browsing nodes
    browse_node_signal = pyqtSignal(object)
    
    def __init__(self, client):
        """Initialize browser widget
        
        Args:
            client: OPC UA client instance
        """
        super().__init__()
        self.client = client
        
        # Set up UI
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        
        # Create toolbar
        self.toolbar = QToolBar("Browser Toolbar")
        self.layout.addWidget(self.toolbar)
        
        # Add refresh action
        self.refresh_action = QAction("Refresh", self)
        self.refresh_action.setIcon(QIcon.fromTheme("view-refresh"))
        self.refresh_action.triggered.connect(self.refresh_current_node)
        self.toolbar.addAction(self.refresh_action)
        
        # Add subscribe action
        self.subscribe_action = QAction("Subscribe", self)
        self.subscribe_action.setIcon(QIcon.fromTheme("list-add"))
        self.subscribe_action.triggered.connect(self.subscribe_selected_node)
        self.toolbar.addAction(self.subscribe_action)
        
        # Add register action
        self.register_action = QAction("Register", self)
        self.register_action.setIcon(QIcon.fromTheme("bookmark-new"))
        self.register_action.triggered.connect(self.register_selected_node)
        self.toolbar.addAction(self.register_action)
        
        # Create splitter
        self.splitter = QSplitter(Qt.Horizontal)
        self.layout.addWidget(self.splitter)
        
        # Create tree view
        self.tree_model = QStandardItemModel()
        self.tree_model.setHorizontalHeaderLabels(["Nodes"])
        
        self.tree_view = QTreeView()
        self.tree_view.setModel(self.tree_model)
        self.tree_view.setHeaderHidden(False)
        self.tree_view.setUniformRowHeights(True)
        self.tree_view.setExpandsOnDoubleClick(True)
        self.tree_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree_view.customContextMenuRequested.connect(self.show_context_menu)
        self.tree_view.expanded.connect(self.on_item_expanded)
        self.tree_view.clicked.connect(self.on_item_clicked)
        
        self.splitter.addWidget(self.tree_view)
        
        # Create details tab widget
        self.details_tabs = QTabWidget()
        self.splitter.addWidget(self.details_tabs)
        
        # Create attributes tab
        self.attributes_table = QTableWidget()
        self.attributes_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.attributes_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.attributes_table.setColumnCount(2)
        self.attributes_table.setHorizontalHeaderLabels(["Attribute", "Value"])
        self.attributes_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.attributes_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.details_tabs.addTab(self.attributes_table, "Attributes")
        
        # Create references tab
        self.references_table = QTableWidget()
        self.references_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.references_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.references_table.setColumnCount(4)
        self.references_table.setHorizontalHeaderLabels(["ReferenceType", "NodeId", "BrowseName", "NodeClass"])
        self.references_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.details_tabs.addTab(self.references_table, "References")
        
        # Create value editor tab
        self.value_widget = QWidget()
        self.value_layout = QVBoxLayout(self.value_widget)
        
        self.value_label = QLabel("Value:")
        self.value_layout.addWidget(self.value_label)
        
        self.value_edit = QLineEdit()
        self.value_layout.addWidget(self.value_edit)
        
        self.value_type_combo = QComboBox()
        self.value_type_combo.addItems(["String", "Boolean", "Int32", "UInt32", "Float", "Double", "DateTime"])
        self.value_layout.addWidget(self.value_type_combo)
        
        self.write_button = QPushButton("Write Value")
        self.write_button.clicked.connect(self.write_value)
        self.value_layout.addWidget(self.write_button)
        
        self.value_layout.addStretch(1)
        
        self.details_tabs.addTab(self.value_widget, "Value")
        
        # Set initial splitter sizes
        self.splitter.setSizes([300, 700])
        
        # Connect client signals
        self.client.browse_complete.connect(self.on_browse_complete)
        self.client.node_attributes_read.connect(self.on_node_attributes_read)
        self.client.node_references_read.connect(self.on_node_references_read)
        self.client.node_read_complete.connect(self.on_node_read_complete)
        self.client.connection_established.connect(self.on_connection_established)
        
        # Connect our browse_node_signal to the main window's browse_node_signal
        # This is what was missing!
        self.browse_node_signal.connect(self.browse_node)
        
        # Initialize tree with root nodes
        self.root_initialized = False
    
    def on_connection_established(self):
        """Handle connection established event"""
        # Initialize root nodes
        self.initialize_root_nodes()
    
    def initialize_root_nodes(self):
        """Initialize root nodes in tree view"""
        if self.root_initialized or not self.client.client:
            return
            
        self.tree_model.removeRows(0, self.tree_model.rowCount())
        
        try:
            # Create root node
            root_node = self.client.client.nodes.root
            root_item = OpcUaTreeItem("Root", root_node)
            self.tree_model.appendRow(root_item)
            
            # Create objects node
            objects_node = self.client.client.nodes.objects
            objects_item = OpcUaTreeItem("Objects", objects_node)
            self.tree_model.appendRow(objects_item)
            
            # Create types node
            types_node = self.client.client.nodes.types
            types_item = OpcUaTreeItem("Types", types_node)
            self.tree_model.appendRow(types_item)
            
            # Create views node
            views_node = self.client.client.nodes.views
            views_item = OpcUaTreeItem("Views", views_node)
            self.tree_model.appendRow(views_item)
            
            self.root_initialized = True
            
        except Exception as e:
            logger.error(f"Error initializing root nodes: {e}")
    
    def on_item_expanded(self, index):
        """Handle item expanded event
        
        Args:
            index: Expanded item index
        """
        item = self.tree_model.itemFromIndex(index)
        if not isinstance(item, OpcUaTreeItem):
            return
            
        if not item.is_loaded:
            # Clear placeholder item
            item.removeRows(0, item.rowCount())
            
            # Use our signal instead of client's
            self.browse_node_signal.emit(item.node)
    
    def browse_node(self, node):
        """Browse node function that calls client method
        
        Args:
            node: Node to browse
        """
        # This method calls the actual client method via asyncio
        asyncio.create_task(self.client.browse_node(node))
    
    def on_item_clicked(self, index):
        """Handle item clicked event
        
        Args:
            index: Clicked item index
        """
        item = self.tree_model.itemFromIndex(index)
        if not isinstance(item, OpcUaTreeItem):
            return
            
        # Read node attributes
        asyncio.create_task(self.client.read_node_attributes(item.node))
        
        # Read node references
        asyncio.create_task(self.client.read_node_references(item.node))
        
        # Read node value
        asyncio.create_task(self.client.read_node_value(item.node))
    
    def on_browse_complete(self, parent_node, children):
        """Handle browse complete event
        
        Args:
            parent_node: Parent node
            children: List of child nodes
        """
        # Find parent item in tree
        parent_item = self.find_item_by_node(parent_node)
        if not parent_item:
            logger.warning(f"Parent item not found for node {parent_node}")
            return
            
        # Add child nodes to tree
        for child in children:
            try:
                # Get node details
                node_id = asyncio.run_coroutine_threadsafe(
                    child.read_node_id(), asyncio.get_event_loop()).result()
                    
                browse_name = asyncio.run_coroutine_threadsafe(
                    child.read_browse_name(), asyncio.get_event_loop()).result()
                    
                node_class = asyncio.run_coroutine_threadsafe(
                    child.read_node_class(), asyncio.get_event_loop()).result()
                    
                # Create tree item
                item = OpcUaTreeItem(browse_name.Name, child)
                item.set_node_details(node_id, node_class)
                
                # Add to parent
                parent_item.appendRow(item)
                
            except Exception as e:
                logger.warning(f"Error adding child node to tree: {e}")
        
        # Mark parent as loaded
        parent_item.is_loaded = True
    
    def on_node_attributes_read(self, node, attributes):
        """Handle node attributes read event
        
        Args:
            node: Node object
            attributes: Dictionary of attribute values
        """
        # Clear attributes table
        self.attributes_table.setRowCount(0)
        
        # Add attributes to table
        row = 0
        for name, value in attributes.items():
            self.attributes_table.insertRow(row)
            self.attributes_table.setItem(row, 0, QTableWidgetItem(name))
            
            # Format value based on type
            if name == "Value" and value is not None:
                if isinstance(value, ua.DataValue):
                    value_str = str(value.Value.Value)
                else:
                    value_str = str(value)
            else:
                value_str = str(value)
                
            self.attributes_table.setItem(row, 1, QTableWidgetItem(value_str))
            row += 1
            
        # Select attributes tab
        self.details_tabs.setCurrentIndex(0)
    
    def on_node_references_read(self, node, references):
        """Handle node references read event
        
        Args:
            node: Node object
            references: List of references
        """
        # Clear references table
        self.references_table.setRowCount(0)
        
        # Add references to table
        row = 0
        for ref in references:
            self.references_table.insertRow(row)
            
            # Get reference type name
            ref_type = self.client.client.get_node(ref["ReferenceTypeId"])
            try:
                ref_type_name = asyncio.run_coroutine_threadsafe(
                    ref_type.read_browse_name(), asyncio.get_event_loop()).result().Name
            except:
                ref_type_name = str(ref["ReferenceTypeId"])
                
            self.references_table.setItem(row, 0, QTableWidgetItem(ref_type_name))
            self.references_table.setItem(row, 1, QTableWidgetItem(str(ref["NodeId"])))
            
            if "BrowseName" in ref:
                self.references_table.setItem(row, 2, QTableWidgetItem(ref["BrowseName"].Name))
            else:
                self.references_table.setItem(row, 2, QTableWidgetItem(""))
                
            if "NodeClass" in ref:
                self.references_table.setItem(row, 3, QTableWidgetItem(ua.NodeClass(ref["NodeClass"]).name))
            else:
                self.references_table.setItem(row, 3, QTableWidgetItem(""))
                
            row += 1
    
    def on_node_read_complete(self, node, value):
        """Handle node read complete event
        
        Args:
            node: Node object
            value: Node value
        """
        if value and value.Value and value.Value.Value is not None:
            self.value_edit.setText(str(value.Value.Value))
            
            # Set value type in combo
            value_type = value.Value.VariantType
            if value_type == ua.VariantType.String:
                self.value_type_combo.setCurrentText("String")
            elif value_type == ua.VariantType.Boolean:
                self.value_type_combo.setCurrentText("Boolean")
            elif value_type == ua.VariantType.Int32:
                self.value_type_combo.setCurrentText("Int32")
            elif value_type == ua.VariantType.UInt32:
                self.value_type_combo.setCurrentText("UInt32")
            elif value_type == ua.VariantType.Float:
                self.value_type_combo.setCurrentText("Float")
            elif value_type == ua.VariantType.Double:
                self.value_type_combo.setCurrentText("Double")
            elif value_type == ua.VariantType.DateTime:
                self.value_type_combo.setCurrentText("DateTime")
        else:
            self.value_edit.setText("")
    
    def write_value(self):
        """Write value to selected node"""
        # Get selected node
        indexes = self.tree_view.selectedIndexes()
        if not indexes:
            QMessageBox.warning(self, "Write Value", "No node selected")
            return
            
        item = self.tree_model.itemFromIndex(indexes[0])
        if not isinstance(item, OpcUaTreeItem):
            return
            
        # Get value and type
        value_str = self.value_edit.text()
        value_type = self.value_type_combo.currentText()
        
        # Convert value based on type
        try:
            if value_type == "String":
                value = value_str
            elif value_type == "Boolean":
                value = value_str.lower() in ("true", "1", "yes", "y")
            elif value_type == "Int32":
                value = int(value_str)
            elif value_type == "UInt32":
                value = int(value_str)
            elif value_type == "Float":
                value = float(value_str)
            elif value_type == "Double":
                value = float(value_str)
            elif value_type == "DateTime":
                # This is simplified - datetime handling would require more logic
                value = value_str
            else:
                value = value_str
        except Exception as e:
            QMessageBox.warning(self, "Write Value", f"Error converting value: {e}")
            return
            
        # Write value to node directly
        asyncio.create_task(self.client.write_node_value(item.node, value))
        
        # Read value again to update UI
        asyncio.create_task(self.client.read_node_value(item.node))
    
    def find_item_by_node(self, node):
        """Find tree item by node
        
        Args:
            node: Node to find
            
        Returns:
            Tree item or None if not found
        """
        # Get node ID string
        try:
            node_id = asyncio.run_coroutine_threadsafe(
                node.read_node_id(), asyncio.get_event_loop()).result()
            node_id_str = str(node_id)
        except:
            # If we can't get node ID, try to match by object reference
            node_id_str = None
        
        # Search in root items first
        for i in range(self.tree_model.rowCount()):
            item = self.tree_model.item(i)
            if isinstance(item, OpcUaTreeItem):
                if node_id_str and item.node_id and str(item.node_id) == node_id_str:
                    return item
                if item.node == node:
                    return item
                
                # Recursively search in children
                found_item = self._find_item_recursive(item, node, node_id_str)
                if found_item:
                    return found_item
                    
        return None
    
    def _find_item_recursive(self, parent_item, node, node_id_str):
        """Recursively find tree item by node
        
        Args:
            parent_item: Parent item to search in
            node: Node to find
            node_id_str: Node ID string
            
        Returns:
            Tree item or None if not found
        """
        for i in range(parent_item.rowCount()):
            item = parent_item.child(i)
            if isinstance(item, OpcUaTreeItem):
                if node_id_str and item.node_id and str(item.node_id) == node_id_str:
                    return item
                if item.node == node:
                    return item
                
                # Recursively search in children
                found_item = self._find_item_recursive(item, node, node_id_str)
                if found_item:
                    return found_item
                    
        return None
    
    def refresh_current_node(self):
        """Refresh current node"""
        indexes = self.tree_view.selectedIndexes()
        if not indexes:
            return
            
        item = self.tree_model.itemFromIndex(indexes[0])
        if not isinstance(item, OpcUaTreeItem):
            return
            
        # Clear children
        item.removeRows(0, item.rowCount())
        item.is_loaded = False
        
        # Add placeholder item
        item.appendRow(QStandardItem("Loading..."))
        
        # Expand to trigger loading
        self.tree_view.expand(indexes[0])
    
    def show_context_menu(self, pos):
        """Show context menu for tree view
        
        Args:
            pos: Position
        """
        index = self.tree_view.indexAt(pos)
        if not index.isValid():
            return
            
        item = self.tree_model.itemFromIndex(index)
        if not isinstance(item, OpcUaTreeItem):
            return
            
        # Create context menu
        menu = QMenu(self)
        
        # Add actions
        read_action = menu.addAction("Read Value")
        read_action.triggered.connect(lambda: asyncio.create_task(self.client.read_node_value(item.node)))
        
        subscribe_action = menu.addAction("Subscribe")
        subscribe_action.triggered.connect(lambda: self.subscribe_selected_node())
        
        register_action = menu.addAction("Register")
        register_action.triggered.connect(lambda: self.register_selected_node())
        
        menu.addSeparator()
        
        refresh_action = menu.addAction("Refresh")
        refresh_action.triggered.connect(self.refresh_current_node)
        
        # Show menu
        menu.exec_(self.tree_view.viewport().mapToGlobal(pos))
    
    def subscribe_selected_node(self):
        """Subscribe to selected node"""
        indexes = self.tree_view.selectedIndexes()
        if not indexes:
            QMessageBox.warning(self, "Subscribe", "No node selected")
            return
            
        item = self.tree_model.itemFromIndex(indexes[0])
        if not isinstance(item, OpcUaTreeItem):
            return
            
        # Confirm subscription
        reply = QMessageBox.question(
            self,
            "Subscribe to Node",
            f"Subscribe to node '{item.text()}'?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Create subscription
            asyncio.create_task(self.client.create_subscription([item.node], 1000))
    
    def register_selected_node(self):
        """Register selected node"""
        indexes = self.tree_view.selectedIndexes()
        if not indexes:
            QMessageBox.warning(self, "Register", "No node selected")
            return
            
        item = self.tree_model.itemFromIndex(indexes[0])
        if not isinstance(item, OpcUaTreeItem):
            return
            
        # Ask for node name
        node_name, ok = QInputDialog.getText(
            self,
            "Register Node",
            "Enter name for registered node:",
            QLineEdit.Normal,
            item.text()
        )
        
        if ok and node_name:
            # Register node directly
            asyncio.create_task(self.client.register_node(item.node, node_name))
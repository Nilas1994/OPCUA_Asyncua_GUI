from typing import Dict, Any, Optional, List, Tuple, Union, Set, Callable
import time
import asyncio
from enum import Enum

from PyQt5.QtCore import QObject, pyqtSignal, QTimer

from utils import get_logger

logger = get_logger("node_manager")

class NodeType(Enum):
    """Types of registered nodes"""
    STANDARD = "Standard"  # Regular node
    LIVEBIT = "LiveBit"    # Toggle between True/False at interval
    TOGGLE = "Toggle"      # Manually toggle between True/False
    CUSTOM = "Custom"      # Custom behavior

class NodeManager(QObject):
    """Manager for registered nodes with special behaviors like LiveBit"""
    
    # Signals
    node_value_changed = pyqtSignal(str, object)  # node_id, new_value
    
    def __init__(self, parent=None):
        """Initialize node manager"""
        super().__init__(parent)
        
        # Node storage
        self.nodes = {}  # Dict[node_id, node_info]
        
        # Callback for writing values
        self.write_callback = None
        
        # Timer for LiveBit nodes
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.process_livebit_nodes)
        self.timer.setInterval(100)  # Check every 100ms
        self.timer.start()
        
        # Track last toggle times
        self.last_toggle_time = {}  # Dict[node_id, timestamp]
    
    def register_write_callback(self, callback: Callable[[str, Any, bool], None]) -> None:
        """
        Register callback for writing values
        
        Args:
            callback: Function to call with (node_id, value, save_value)
        """
        self.write_callback = callback
    
    def register_node(self, node_id: str, node_info: Dict[str, Any]) -> None:
        """
        Register a node
        
        Args:
            node_id: Node ID
            node_info: Node information dictionary
        """
        # Ensure required fields
        if "display_name" not in node_info:
            node_info["display_name"] = "Unknown"
        
        if "node_type" not in node_info:
            node_info["node_type"] = NodeType.STANDARD.value
        
        if "toggle_interval" not in node_info:
            node_info["toggle_interval"] = 1.0
        
        # Store node
        self.nodes[node_id] = node_info
        
        # Initialize last toggle time
        if node_info["node_type"] == NodeType.LIVEBIT.value:
            self.last_toggle_time[node_id] = time.time()
        
        logger.info(f"Registered node: {node_id} ({node_info['display_name']})")
    
    def unregister_node(self, node_id: str) -> None:
        """
        Unregister a node
        
        Args:
            node_id: Node ID
        """
        if node_id in self.nodes:
            del self.nodes[node_id]
        
        if node_id in self.last_toggle_time:
            del self.last_toggle_time[node_id]
        
        logger.info(f"Unregistered node: {node_id}")
    
    def set_node_type(self, node_id: str, node_type: NodeType, toggle_interval: Optional[float] = None) -> None:
        """
        Set node type
        
        Args:
            node_id: Node ID
            node_type: Node type
            toggle_interval: Toggle interval for LiveBit nodes
        """
        if node_id not in self.nodes:
            logger.warning(f"Cannot set type for unregistered node: {node_id}")
            return
        
        # Update node type
        self.nodes[node_id]["node_type"] = node_type.value
        
        # Update toggle interval if provided
        if toggle_interval is not None:
            self.nodes[node_id]["toggle_interval"] = toggle_interval
        
        # Initialize last toggle time for LiveBit nodes
        if node_type == NodeType.LIVEBIT:
            self.last_toggle_time[node_id] = time.time()
        
        logger.info(f"Set node {node_id} type to {node_type.value}")
    
    def update_node_value(self, node_id: str, value: Any):
        """
        Update a node's value without writing to the server
        
        Args:
            node_id: Node ID
            value: New value
        """
        if node_id in self.nodes:
            # Update the value in our local storage
            self.nodes[node_id]["last_value"] = value
            
            # Emit signal for UI update
            self.node_value_changed.emit(node_id, value)
            logger.debug(f"Updated node {node_id} value to {value} (without writing)")

    def write_value(self, node_id: str, value: Any, save_value: bool = True) -> bool:
        """
        Write a value to a node
        
        Args:
            node_id: Node ID
            value: Value to write
            save_value: Whether to save the value
            
        Returns:
            True if callback was called, False otherwise
        """
        if node_id not in self.nodes:
            logger.warning(f"Cannot write to unregistered node: {node_id}")
            return False
        
        if self.write_callback is None:
            logger.warning("No write callback registered")
            return False
        
        # Call write callback
        self.write_callback(node_id, value, save_value)
        
        # Update local value if saving
        if save_value:
            self.nodes[node_id]["last_value"] = value
        
        # Emit value changed signal
        self.node_value_changed.emit(node_id, value)
        
        return True
    
    def toggle_value(self, node_id: str) -> bool:
        """
        Toggle boolean value
        
        Args:
            node_id: Node ID
            
        Returns:
            True if toggled, False if error
        """
        if node_id not in self.nodes:
            logger.warning(f"Cannot toggle unregistered node: {node_id}")
            return False
        
        # Check data type
        if "data_type" not in self.nodes[node_id] or self.nodes[node_id]["data_type"] != "Boolean":
            logger.warning(f"Cannot toggle non-boolean node: {node_id}")
            return False
        
        # Get current value
        current_value = self.nodes[node_id].get("last_value")
        if current_value is None:
            new_value = True  # Default to True if no current value
        else:
            new_value = not current_value
        
        # Write new value
        return self.write_value(node_id, new_value)
    
    def process_livebit_nodes(self) -> None:
        """Process LiveBit nodes (toggle boolean values)"""
        current_time = time.time()
        
        for node_id, node_info in list(self.nodes.items()):
            # Skip non-LiveBit nodes
            if node_info.get("node_type") != NodeType.LIVEBIT.value:
                continue
            
            # Skip non-boolean nodes
            if node_info.get("data_type") != "Boolean":
                continue
            
            # Check if it's time to toggle
            if node_id not in self.last_toggle_time:
                self.last_toggle_time[node_id] = current_time
                continue
            
            if current_time - self.last_toggle_time[node_id] >= node_info.get("toggle_interval", 1.0):
                # Toggle the value
                self.toggle_value(node_id)
                
                # Update last toggle time
                self.last_toggle_time[node_id] = current_time
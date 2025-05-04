import os
import json
import time
import shutil
from typing import Dict, Any, Optional, List, Tuple, Union, Set
from datetime import datetime
from threading import Lock

from PyQt5.QtCore import QObject, pyqtSignal, QTimer
from file_watcher import FileWatcher
from utils import get_logger
from config_manager import NodeRegistrationType

logger = get_logger("json_output_manager")

class JsonOutputManager(QObject):
    """Manage JSON output for OPC UA node data"""
    
    # Signals
    json_updated = pyqtSignal(str)  # filename
    write_requested = pyqtSignal(str, object)  # node_id, value
    write_completed = pyqtSignal(str, bool)  # node_id, success
    
    def __init__(self, output_dir: str = None, parent=None):
        """Initialize JSON output manager"""
        super().__init__(parent)
        
        # Set output directory
        if output_dir is None:
            from utils import get_output_dir
            output_dir = get_output_dir()
        
        self.output_dir = output_dir
        
        # Create directories for individual node files
        self.subscriptions_dir = os.path.join(output_dir, "subscriptions")
        self.registered_nodes_dir = os.path.join(output_dir, "registered_nodes")
        self.custom_nodes_dir = os.path.join(self.registered_nodes_dir, "custom")
        
        # Create directories
        for dir_path in [self.subscriptions_dir, self.registered_nodes_dir, self.custom_nodes_dir]:
            os.makedirs(dir_path, exist_ok=True)
        
        # Data storage for quick access
        self.subscriptions_data = {}  # Dict[node_id, node_info]
        self.registered_nodes_data = {}  # Dict[node_id, node_info]
        
        # Thread safety
        self.lock = Lock()
        
        # Track active write requests
        self.active_write_requests = {}  # Dict[node_id, (filepath, timestamp)]
        
        # Initialize files
        self._init_index_files()
        
        # Add file watcher for custom nodes
        self.file_watcher = FileWatcher(self.custom_nodes_dir, self)
        self.file_watcher.file_changed.connect(self.on_file_changed)

        # Add periodic check timer for write requests
        self.check_timer = QTimer()
        self.check_timer.timeout.connect(self.check_write_requests)
        self.check_timer.start(500)  # Check every 500ms

        logger.info(f"JsonOutputManager initialized with output dir: {output_dir}")


    def on_file_changed(self, filepath: str):
        """Handle file change - check for write requests with improved validation"""
        try:
            if not os.path.exists(filepath):
                return
                
            # Read file content
            with open(filepath, 'r') as f:
                node_data = json.load(f)
            
            node_id = node_data.get("node_id")
            if not node_id:
                logger.warning(f"No node_id found in file: {filepath}")
                return
            
            # Check metadata and if file has write_requested flag
            metadata = node_data.get("metadata", {})
            write_requested = metadata.get("write_requested", False)
            
            if write_requested:
                value = node_data.get("value")
                logger.info(f"Write request detected for node {node_id}: {value}")
                
                # Always check if we don't have an active write request for this node
                if node_id not in self.active_write_requests:
                    # Request write to OPC UA server
                    self.request_write(node_id, value, filepath)
                else:
                    logger.debug(f"Write request already in progress for {node_id}")
            
            # Update internal data
            self.registered_nodes_data[node_id] = node_data
            self.json_updated.emit(filepath)
            
        except Exception as e:
            logger.error(f"Error processing file change for {filepath}: {str(e)}")

    
    def request_write(self, node_id: str, value: Any, filepath: str):
        """Request a write operation"""
        timestamp = datetime.now().isoformat()
        self.active_write_requests[node_id] = (filepath, timestamp)
        self.write_requested.emit(node_id, value)
        logger.info(f"Write requested for node {node_id} with value {value}")
    
    def mark_write_completed(self, node_id: str, success: bool):
        """Mark write operation as completed and update file"""
        if node_id in self.active_write_requests:
            filepath, _ = self.active_write_requests[node_id]
            del self.active_write_requests[node_id]
            
            # Update file to remove write_requested flag
            try:
                if os.path.exists(filepath):
                    with open(filepath, 'r') as f:
                        node_data = json.load(f)
                    
                    # Reset write_requested flag
                    metadata = node_data.get("metadata", {})
                    metadata["write_requested"] = False
                    metadata["last_write_status"] = "success" if success else "failed"
                    metadata["last_write_time"] = datetime.now().isoformat()
                    node_data["metadata"] = metadata
                    
                    # Write back to file
                    with open(filepath, 'w') as f:
                        json.dump(node_data, f, indent=2)
                    
                    logger.info(f"Write completed for node {node_id} - {'success' if success else 'failed'}")
                    
                    # Emit completion signal
                    self.write_completed.emit(node_id, success)
            except Exception as e:
                logger.error(f"Error updating file after write completion: {e}")

    def _init_index_files(self):
        """Initialize index files for fast access"""
        try:
            # Create index files for tracking active nodes
            subscriptions_index_file = os.path.join(self.subscriptions_dir, "_index.json")
            registered_index_file = os.path.join(self.registered_nodes_dir, "_index.json")
            
            if not os.path.exists(subscriptions_index_file):
                self._save_index(subscriptions_index_file, {})
            
            if not os.path.exists(registered_index_file):
                self._save_index(registered_index_file, {})
            
            logger.info(f"JSON output directories initialized in {self.output_dir}")
        except Exception as e:
            logger.error(f"Error initializing JSON directories: {str(e)}")
    
    def _save_index(self, filepath: str, data: Dict[str, Any]):
        """Save index file for fast access"""
        try:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, sort_keys=True)
        except Exception as e:
            logger.error(f"Error saving index file {filepath}: {str(e)}")
    
    def _load_index(self, filepath: str) -> Dict[str, Any]:
        """Load index file"""
        try:
            if os.path.exists(filepath):
                with open(filepath, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            logger.error(f"Error loading index file {filepath}: {str(e)}")
            return {}
    
    def _get_safe_filename(self, node_id: str) -> str:
        """Convert node ID to safe filename"""
        # Replace invalid characters with underscores
        safe_name = node_id.replace('=', '_').replace(';', '_').replace('/', '_').replace('\\', '_')
        return f"{safe_name}.json"
    
    def add_subscription(self, node_id: str, display_name: str, value: Any, parent_path: Optional[str] = None):
        """
        Add or update a subscription
        
        Args:
            node_id: Node ID
            display_name: Display name
            value: Current value
            parent_path: Parent path in OPC UA structure
        """
        with self.lock:
            timestamp = datetime.now().isoformat()
            
            # Prepare node data
            node_data = {
                "node_id": node_id,
                "display_name": display_name,
                "value": self._serialize_value(value),
                "timestamp": timestamp,
                "parent_path": parent_path,
                "metadata": {
                    "last_updated": timestamp,
                    "subscription_active": True
                }
            }
            
            # Save to individual file
            filepath = os.path.join(self.subscriptions_dir, self._get_safe_filename(node_id))
            try:
                with open(filepath, 'w') as f:
                    json.dump(node_data, f, indent=2)
                
                # Update index
                index = self._load_index(os.path.join(self.subscriptions_dir, "_index.json"))
                index[node_id] = {
                    "display_name": display_name,
                    "filepath": filepath,
                    "last_updated": timestamp
                }
                self._save_index(os.path.join(self.subscriptions_dir, "_index.json"), index)
                
                # Update in-memory data
                self.subscriptions_data[node_id] = node_data
                
                # Emit signal
                self.json_updated.emit(filepath)
                
            except Exception as e:
                logger.error(f"Error saving subscription node {node_id}: {str(e)}")
    
    def add_registered_node(self, node_id: str, node_info: Dict[str, Any], structure_info: Optional[Dict[str, Any]] = None):
        """
        Add or update a registered node
        
        Args:
            node_id: Node ID
            node_info: Node information dictionary
            structure_info: Structure information
        """
        with self.lock:
            timestamp = datetime.now().isoformat()
            
            # Prepare node data
            node_data = {
                "node_id": node_id,
                "display_name": node_info.get("display_name", "Unknown"),
                "node_type": node_info.get("node_type", "Standard"),
                "data_type": node_info.get("data_type", "Unknown"),
                "value": self._serialize_value(node_info.get("last_value")),
                "toggle_interval": node_info.get("toggle_interval", 1.0),
                "writeable": node_info.get("writeable", False),
                "timestamp": timestamp,
                "structure": structure_info,
                "metadata": {
                    "last_updated": timestamp,
                    "registration_active": True,
                    "write_requested": False  # Flag to trigger writes from external edits
                }
            }
            
            # Save to appropriate directory based on node type
            is_custom = node_data["node_type"] == "Custom"
            directory = self.custom_nodes_dir if is_custom else self.registered_nodes_dir
            
            filepath = os.path.join(directory, self._get_safe_filename(node_id))
            try:
                with open(filepath, 'w') as f:
                    json.dump(node_data, f, indent=2)
                
                # Update index
                index = self._load_index(os.path.join(self.registered_nodes_dir, "_index.json"))
                index[node_id] = {
                    "display_name": node_data["display_name"],
                    "node_type": node_data["node_type"],
                    "filepath": filepath,
                    "is_custom": is_custom,
                    "last_updated": timestamp
                }
                self._save_index(os.path.join(self.registered_nodes_dir, "_index.json"), index)
                
                # Update in-memory data
                self.registered_nodes_data[node_id] = node_data
                
                # Emit signal
                self.json_updated.emit(filepath)
                
            except Exception as e:
                logger.error(f"Error saving registered node {node_id}: {str(e)}")
    
    def update_subscription_value(self, node_id: str, value: Any):
        """
        Update subscription value and timestamp
        
        Args:
            node_id: Node ID
            value: New value
        """
        with self.lock:
            filepath = os.path.join(self.subscriptions_dir, self._get_safe_filename(node_id))
            
            if os.path.exists(filepath):
                try:
                    # Load current data
                    with open(filepath, 'r') as f:
                        node_data = json.load(f)
                    
                    # Update value and timestamp
                    timestamp = datetime.now().isoformat()
                    node_data["value"] = self._serialize_value(value)
                    node_data["timestamp"] = timestamp
                    node_data["metadata"]["last_updated"] = timestamp
                    
                    # Save updated data
                    with open(filepath, 'w') as f:
                        json.dump(node_data, f, indent=2)
                    
                    # Update in-memory data
                    self.subscriptions_data[node_id] = node_data
                    
                    # Emit signal
                    self.json_updated.emit(filepath)
                    
                except Exception as e:
                    logger.error(f"Error updating subscription value for {node_id}: {str(e)}")
    
    def update_registered_node_value(self, node_id: str, value: Any):
        """Update registered node value avoiding conflicts"""
        with self.lock:
            # Find the correct filepath using index
            index = self._load_index(os.path.join(self.registered_nodes_dir, "_index.json"))
            
            if node_id in index:
                filepath = index[node_id]["filepath"]
                
                # Don't update file if there's an active write request
                if node_id in self.active_write_requests:
                    logger.debug(f"Skipping value update for {node_id} - write in progress")
                    return
                
                if os.path.exists(filepath):
                    try:
                        # Load current data
                        with open(filepath, 'r') as f:
                            node_data = json.load(f)
                        
                        # Update value and timestamp
                        timestamp = datetime.now().isoformat()
                        node_data["value"] = self._serialize_value(value)
                        node_data["timestamp"] = timestamp
                        node_data["metadata"]["last_updated"] = timestamp
                        
                        # Don't change write_requested flag
                        write_requested = node_data.get("metadata", {}).get("write_requested", False)
                        
                        # Save updated data
                        with open(filepath, 'w') as f:
                            json.dump(node_data, f, indent=2)
                        
                        # Update in-memory data
                        self.registered_nodes_data[node_id] = node_data
                        
                        # Only emit signal if not waiting for write
                        if not write_requested:
                            self.json_updated.emit(filepath)
                        
                    except Exception as e:
                        logger.error(f"Error updating registered node value for {node_id}: {str(e)}")
    
    def trigger_manual_write(self, node_id: str):
        """Manually trigger a write request for testing"""
        index = self._load_index(os.path.join(self.registered_nodes_dir, "_index.json"))
        
        if node_id in index:
            filepath = index[node_id]["filepath"]
            
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r') as f:
                        node_data = json.load(f)
                    
                    # Ensure metadata exists
                    if "metadata" not in node_data:
                        node_data["metadata"] = {}
                    
                    # Set write_requested flag
                    node_data["metadata"]["write_requested"] = True
                    node_data["metadata"]["write_request_time"] = datetime.now().isoformat()
                    
                    # Save to file to trigger file watcher
                    with open(filepath, 'w') as f:
                        json.dump(node_data, f, indent=2)
                    
                    logger.info(f"Manually triggered write request for node {node_id}")
                    
                except Exception as e:
                    logger.error(f"Error manually triggering write for {node_id}: {e}")

    def remove_subscription(self, node_id: str):
        """
        Remove a subscription
        
        Args:
            node_id: Node ID
        """
        with self.lock:
            filepath = os.path.join(self.subscriptions_dir, self._get_safe_filename(node_id))
            
            try:
                # Remove file
                if os.path.exists(filepath):
                    os.remove(filepath)
                
                # Update index
                index = self._load_index(os.path.join(self.subscriptions_dir, "_index.json"))
                if node_id in index:
                    del index[node_id]
                    self._save_index(os.path.join(self.subscriptions_dir, "_index.json"), index)
                
                # Remove from in-memory data
                if node_id in self.subscriptions_data:
                    del self.subscriptions_data[node_id]
                
                logger.info(f"Removed subscription for node {node_id}")
                
            except Exception as e:
                logger.error(f"Error removing subscription {node_id}: {str(e)}")
    
    def remove_registered_node(self, node_id: str):
        """
        Remove a registered node
        
        Args:
            node_id: Node ID
        """
        with self.lock:
            # Find filepath using index
            index = self._load_index(os.path.join(self.registered_nodes_dir, "_index.json"))
            
            if node_id in index:
                filepath = index[node_id]["filepath"]
                
                try:
                    # Remove file
                    if os.path.exists(filepath):
                        os.remove(filepath)
                    
                    # Update index
                    del index[node_id]
                    self._save_index(os.path.join(self.registered_nodes_dir, "_index.json"), index)
                    
                    # Remove from in-memory data
                    if node_id in self.registered_nodes_data:
                        del self.registered_nodes_data[node_id]
                    
                    logger.info(f"Removed registered node {node_id}")
                    
                except Exception as e:
                    logger.error(f"Error removing registered node {node_id}: {str(e)}")
    
    def check_write_requests(self):
        """Periodically check for write requests - backup mechanism"""
        try:
            if not os.path.exists(self.custom_nodes_dir):
                return
                            
            for filename in os.listdir(self.custom_nodes_dir):
                if filename.endswith('.json'):
                    filepath = os.path.join(self.custom_nodes_dir, filename)
                                        
                    try:
                        with open(filepath, 'r') as f:
                            node_data = json.load(f)
                                                
                        node_id = node_data.get("node_id")
                        metadata = node_data.get("metadata", {})
                                                
                        # Check for write request
                        if metadata.get("write_requested", False) and node_id:
                            if node_id not in self.active_write_requests:
                                value = node_data.get("value")
                                logger.info(f"Periodic check: Write request for {node_id}")
                                self.request_write(node_id, value, filepath)
                    except Exception as e:
                        logger.error(f"Error checking file {filepath}: {e}")
                                    
        except Exception as e:
            logger.error(f"Error in periodic write check: {e}")
    
    def request_write(self, node_id: str, value: Any, filepath: str):
        """Request a write operation with improved tracking"""
        timestamp = datetime.now().isoformat()
        
        # Store active write request
        self.active_write_requests[node_id] = (filepath, timestamp)
        
        # Emit write request signal
        self.write_requested.emit(node_id, value)
        
        logger.info(f"Write requested for node {node_id} with value {value}")
    
    def update_custom_node_type(self, node_id: str, new_type: str):
        """
        Update a node's type and move file if necessary
        
        Args:
            node_id: Node ID
            new_type: New node type
        """
        with self.lock:
            index = self._load_index(os.path.join(self.registered_nodes_dir, "_index.json"))
            
            if node_id in index:
                current_filepath = index[node_id]["filepath"]
                current_type = index[node_id]["node_type"]
                
                if current_type != new_type:
                    # Determine new directory
                    is_custom = new_type == "Custom"
                    new_directory = self.custom_nodes_dir if is_custom else self.registered_nodes_dir
                    new_filepath = os.path.join(new_directory, self._get_safe_filename(node_id))
                    
                    try:
                        # Load current data
                        with open(current_filepath, 'r') as f:
                            node_data = json.load(f)
                        
                        # Update node type
                        node_data["node_type"] = new_type
                        node_data["metadata"]["last_updated"] = datetime.now().isoformat()
                        
                        # Save to new location
                        with open(new_filepath, 'w') as f:
                            json.dump(node_data, f, indent=2)
                        
                        # Remove old file
                        os.remove(current_filepath)
                        
                        # Update index
                        index[node_id]["node_type"] = new_type
                        index[node_id]["filepath"] = new_filepath
                        index[node_id]["is_custom"] = is_custom
                        self._save_index(os.path.join(self.registered_nodes_dir, "_index.json"), index)
                        
                        logger.info(f"Moved node {node_id} from {current_type} to {new_type}")
                        
                    except Exception as e:
                        logger.error(f"Error moving node {node_id}: {str(e)}")
    
    def _serialize_value(self, value: Any) -> Any:
        """
        Serialize value for JSON output
        
        Args:
            value: Value to serialize
            
        Returns:
            Serialized value
        """
        if value is None:
            return None
        
        # Handle datetime objects
        if isinstance(value, datetime):
            return value.isoformat()
        
        # Handle other non-serializable objects
        try:
            json.dumps(value)
            return value
        except (TypeError, ValueError):
            return str(value)
    
    def read_custom_nodes(self) -> Dict[str, Any]:
        """
        Read and return custom nodes for external editing
        
        Returns:
            Dictionary of custom nodes
        """
        custom_nodes = {}
        
        try:
            if os.path.exists(self.custom_nodes_dir):
                for filename in os.listdir(self.custom_nodes_dir):
                    if filename.endswith('.json'):
                        filepath = os.path.join(self.custom_nodes_dir, filename)
                        
                        with open(filepath, 'r') as f:
                            node_data = json.load(f)
                            custom_nodes[node_data["node_id"]] = node_data
            
            return custom_nodes
        except Exception as e:
            logger.error(f"Error reading custom nodes: {str(e)}")
            return {}
    
    def update_custom_nodes(self, custom_nodes: Dict[str, Any]) -> bool:
        """
        Update custom nodes from external source
        
        Args:
            custom_nodes: Dictionary of custom nodes
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with self.lock:
                for node_id, node_data in custom_nodes.items():
                    filepath = os.path.join(self.custom_nodes_dir, self._get_safe_filename(node_id))
                    
                    # Ensure node_id is set correctly
                    node_data["node_id"] = node_id
                    node_data["metadata"]["last_updated"] = datetime.now().isoformat()
                    
                    # Save updated node data
                    with open(filepath, 'w') as f:
                        json.dump(node_data, f, indent=2)
                    
                    # Update in-memory data
                    self.registered_nodes_data[node_id] = node_data
                
                return True
        except Exception as e:
            logger.error(f"Error updating custom nodes: {str(e)}")
            return False
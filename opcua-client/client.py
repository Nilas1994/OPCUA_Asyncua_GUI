#!/usr/bin/env python3
"""
OPC UA Client implementation
"""
import asyncio
import logging
import time
import json
from pathlib import Path
from typing import Dict, List, Optional, Callable, Any, Tuple, Set, Union
from enum import Enum
import random
from datetime import datetime

from asyncua import Client, ua
from asyncua.crypto import security_policies
from asyncua.common.subscription import Subscription
from asyncua.common.node import Node

from PyQt5.QtCore import QObject, pyqtSignal

logger = logging.getLogger(__name__)

# Security policy mapping as required
SECURITY_POLICY_MAP = {
    "NO_SECURITY": (None, ua.MessageSecurityMode.None_),
    "BASIC128RSA15_SIGN": (security_policies.SecurityPolicyBasic128Rsa15, ua.MessageSecurityMode.Sign),
    "BASIC128RSA15_SIGN_ENCRYPT": (security_policies.SecurityPolicyBasic128Rsa15, ua.MessageSecurityMode.SignAndEncrypt),
    "BASIC256_SIGN": (security_policies.SecurityPolicyBasic256, ua.MessageSecurityMode.Sign),
    "BASIC256_SIGN_ENCRYPT": (security_policies.SecurityPolicyBasic256, ua.MessageSecurityMode.SignAndEncrypt),
    "BASIC256SHA256_SIGN": (security_policies.SecurityPolicyBasic256Sha256, ua.MessageSecurityMode.Sign),
    "BASIC256SHA256_SIGN_ENCRYPT": (security_policies.SecurityPolicyBasic256Sha256, ua.MessageSecurityMode.SignAndEncrypt),
    "AES128SHA256RSAOAEP_SIGN": (security_policies.SecurityPolicyAes128Sha256RsaOaep, ua.MessageSecurityMode.Sign),
    "AES128SHA256RSAOAEP_SIGN_ENCRYPT": (security_policies.SecurityPolicyAes128Sha256RsaOaep, ua.MessageSecurityMode.SignAndEncrypt),
    "AES256SHA256RSAPSS_SIGN": (security_policies.SecurityPolicyAes256Sha256RsaPss, ua.MessageSecurityMode.Sign),
    "AES256SHA256RSAPSS_SIGN_ENCRYPT": (security_policies.SecurityPolicyAes256Sha256RsaPss, ua.MessageSecurityMode.SignAndEncrypt),
}


class ConnectionStatus(Enum):
    """Connection status enum"""
    DISCONNECTED = 0
    CONNECTING = 1
    CONNECTED = 2
    ERROR = 3


class DataChangeHandler(QObject):
    """Handler for subscription data changes with Qt signals"""
    
    data_change = pyqtSignal(str, Node, object, object)
    event = pyqtSignal(str, object)
    
    def __init__(self, subscription_id: str):
        super().__init__()
        self.subscription_id = subscription_id
        
    def datachange_notification(self, node: Node, val, data):
        """Called when a subscribed node's value changes"""
        logger.debug(f"Subscription {self.subscription_id}: Data change notification for {node}, value: {val}")
        self.data_change.emit(self.subscription_id, node, val, data)
        
    def event_notification(self, event):
        """Called when a subscribed event occurs"""
        logger.debug(f"Subscription {self.subscription_id}: Event notification: {event}")
        self.event.emit(self.subscription_id, event)


class OpcUaClient(QObject):
    """OPC UA Client implementation with asyncio and Qt signals"""
    
    # Signal definitions
    connection_status_changed = pyqtSignal(ConnectionStatus, str)
    connection_established = pyqtSignal()
    connection_lost = pyqtSignal(str)
    browse_complete = pyqtSignal(Node, list)
    node_read_complete = pyqtSignal(Node, ua.DataValue)
    node_write_complete = pyqtSignal(Node, bool)
    node_attributes_read = pyqtSignal(Node, dict)
    node_references_read = pyqtSignal(Node, list)
    subscription_created = pyqtSignal(str, Subscription)
    subscription_data_change = pyqtSignal(str, Node, object, object)
    subscription_event = pyqtSignal(str, object)
    registered_node_added = pyqtSignal(str, Node)
    registered_node_removed = pyqtSignal(str)
    log_message = pyqtSignal(str, str)  # level, message
    
    def __init__(self):
        super().__init__()
        
        # Client instance and connection properties
        self.client = None
        self.endpoint_url = ""
        self.status = ConnectionStatus.DISCONNECTED
        self.reconnect_task = None
        self.auto_reconnect = True
        self.initial_reconnect_delay = 5
        self.max_reconnect_delay = 60
        self.max_reconnect_attempts = 0  # 0 means infinite
        self.reconnect_attempt = 0
        
        # Authentication and security
        self.username = None
        self.password = None
        self.security_policy = "NO_SECURITY"
        self.certificate_path = None
        self.private_key_path = None
        
        # Subscriptions storage
        self.subscriptions: Dict[str, Tuple[Subscription, DataChangeHandler]] = {}
        
        # Registered nodes
        self.registered_nodes: Dict[str, Node] = {}
        self.registered_node_ids: Dict[str, ua.NodeId] = {}
        
        # LiveBit functionality
        self.livebit_tasks: Dict[str, asyncio.Task] = {}
        self.livebit_interval = 5  # seconds
        
        # Node caching for better performance
        self.node_cache: Dict[str, Node] = {}
    
    def log(self, level: str, message: str) -> None:
        """Log a message both to logger and emit as a signal"""
        getattr(logger, level.lower())(message)
        self.log_message.emit(level, message)
    
    async def connect(self, endpoint_url: str, username: Optional[str] = None, 
                     password: Optional[str] = None, security_policy: Optional[str] = None,
                     certificate: Optional[str] = None, private_key: Optional[str] = None) -> bool:
        """Connect to OPC UA server
        
        Args:
            endpoint_url: Server endpoint URL
            username: Optional username
            password: Optional password
            security_policy: Security policy to use
            certificate: Path to client certificate
            private_key: Path to client private key
            
        Returns:
            True if connection successful, False otherwise
        """
        if self.status == ConnectionStatus.CONNECTED:
            self.log("INFO", f"Already connected to {self.endpoint_url}")
            return True
        
        if self.status == ConnectionStatus.CONNECTING:
            self.log("WARNING", "Connection already in progress, please wait")
            return False
        
        # Update connection parameters
        self.endpoint_url = endpoint_url
        self.username = username
        self.password = password
        
        if security_policy:
            self.security_policy = security_policy
        if certificate:
            self.certificate_path = certificate
        if private_key:
            self.private_key_path = private_key
            
        # Set connection status
        self.status = ConnectionStatus.CONNECTING
        self.connection_status_changed.emit(ConnectionStatus.CONNECTING, "Connecting...")
        
        try:
            self.log("INFO", f"Connecting to {endpoint_url}")
            
            # Create new client instance
            self.client = Client(endpoint_url)
            
            # Set security if needed
            if self.security_policy != "NO_SECURITY":
                policy_class, mode = SECURITY_POLICY_MAP[self.security_policy]
                if policy_class and self.certificate_path and self.private_key_path:
                    await self.client.set_security(
                        policy_class(),
                        self.certificate_path,
                        self.private_key_path,
                        mode=mode
                    )
            
            # Set user authentication if provided
            if self.username and self.password:
                self.client.set_user(self.username)
                self.client.set_password(self.password)
            
            # Connect to server
            await self.client.connect()
            
            # Get server endpoints after connection
            self.log("INFO", "Retrieving server endpoints")
            endpoints = await self.client.get_endpoints()
            supported_policies = []
            for endpoint in endpoints:
                policy_uri = endpoint.SecurityPolicyUri.split("#")[1] if "#" in endpoint.SecurityPolicyUri else "None"
                mode_str = ua.MessageSecurityMode(endpoint.SecurityMode).name
                supported_policies.append(f"{policy_uri}/{mode_str}")
            
            self.log("INFO", f"Server supports security policies: {', '.join(supported_policies)}")
            
            # Update connection status
            self.status = ConnectionStatus.CONNECTED
            self.reconnect_attempt = 0
            self.connection_status_changed.emit(ConnectionStatus.CONNECTED, "Connected")
            self.connection_established.emit()
            
            # Set up monitoring for disconnection
            self._start_monitoring()
            
            self.log("INFO", f"Successfully connected to {endpoint_url}")
            return True
            
        except Exception as e:
            error_msg = f"Failed to connect: {str(e)}"
            self.log("ERROR", error_msg)
            self.status = ConnectionStatus.ERROR
            self.connection_status_changed.emit(ConnectionStatus.ERROR, error_msg)
            
            # Start reconnection if enabled
            if self.auto_reconnect:
                self._start_reconnect()
                
            return False
    
    async def disconnect(self) -> None:
        """Disconnect from OPC UA server"""
        # Stop reconnection attempts if running
        if self.reconnect_task and not self.reconnect_task.done():
            self.reconnect_task.cancel()
            self.reconnect_task = None
        
        # Stop all LiveBit tasks
        for task_id, task in list(self.livebit_tasks.items()):
            if not task.done():
                task.cancel()
            self.livebit_tasks.pop(task_id)
            
        if not self.client:
            self.status = ConnectionStatus.DISCONNECTED
            self.connection_status_changed.emit(ConnectionStatus.DISCONNECTED, "Disconnected")
            return
            
        try:
            if self.status == ConnectionStatus.CONNECTED:
                self.log("INFO", "Disconnecting from server")
                
                # Remove all subscriptions
                for sub_id, (sub, _) in list(self.subscriptions.items()):
                    try:
                        await sub.delete()
                    except Exception as e:
                        self.log("WARNING", f"Error removing subscription {sub_id}: {e}")
                
                self.subscriptions.clear()
                
                # Disconnect client
                await self.client.disconnect()
                
            self.status = ConnectionStatus.DISCONNECTED
            self.connection_status_changed.emit(ConnectionStatus.DISCONNECTED, "Disconnected")
            self.log("INFO", "Disconnected from server")
            
        except Exception as e:
            error_msg = f"Error during disconnect: {str(e)}"
            self.log("ERROR", error_msg)
            self.status = ConnectionStatus.ERROR
            self.connection_status_changed.emit(ConnectionStatus.ERROR, error_msg)
        finally:
            self.client = None
    
    async def browse_node(self, node: Union[Node, str, ua.NodeId]) -> List[Node]:
        """Browse child nodes
        
        Args:
            node: Parent node to browse (Node object, NodeId or string)
            
        Returns:
            List of child nodes
        """
        if not self._check_connection():
            return []
            
        try:
            # Get the node object if string or NodeId was passed
            if isinstance(node, str):
                node = self.client.get_node(node)
            elif isinstance(node, ua.NodeId):
                node = self.client.get_node(node)
                
            # Browse children
            self.log("DEBUG", f"Browsing children of node {node}")
            children = await node.get_children()
            
            # Update node cache
            for child in children:
                node_id = await child.read_node_id()
                self.node_cache[str(node_id)] = child
                
            # Emit signal with results
            self.browse_complete.emit(node, children)
            return children
            
        except Exception as e:
            self.log("ERROR", f"Error browsing node {node}: {str(e)}")
            return []
    
    async def read_node_value(self, node: Union[Node, str, ua.NodeId]) -> Optional[ua.DataValue]:
        """Read node value
        
        Args:
            node: Node to read (Node object, NodeId or string)
            
        Returns:
            Node value as DataValue or None if error
        """
        if not self._check_connection():
            return None
            
        try:
            # Get the node object if string or NodeId was passed
            if isinstance(node, str):
                node = self.client.get_node(node)
            elif isinstance(node, ua.NodeId):
                node = self.client.get_node(node)
                
            # Read value
            self.log("DEBUG", f"Reading value of node {node}")
            value = await node.read_data_value()
            
            # Emit signal with result
            self.node_read_complete.emit(node, value)
            return value
            
        except Exception as e:
            self.log("ERROR", f"Error reading node value {node}: {str(e)}")
            return None
    
    async def write_node_value(self, node: Union[Node, str, ua.NodeId], value: Any) -> bool:
        """Write value to node
        
        Args:
            node: Node to write to (Node object, NodeId or string)
            value: Value to write
            
        Returns:
            True if successful, False otherwise
        """
        if not self._check_connection():
            return False
            
        try:
            # Get the node object if string or NodeId was passed
            if isinstance(node, str):
                node = self.client.get_node(node)
            elif isinstance(node, ua.NodeId):
                node = self.client.get_node(node)
                
            # Write value
            self.log("DEBUG", f"Writing value {value} to node {node}")
            await node.write_value(value)
            
            # Emit signal with result
            self.node_write_complete.emit(node, True)
            return True
            
        except Exception as e:
            self.log("ERROR", f"Error writing value to node {node}: {str(e)}")
            self.node_write_complete.emit(node, False)
            return False
    
    async def read_node_attributes(self, node: Union[Node, str, ua.NodeId]) -> Dict[str, Any]:
        """Read all attributes of a node
        
        Args:
            node: Node to read attributes from (Node object, NodeId or string)
            
        Returns:
            Dictionary of attribute values
        """
        if not self._check_connection():
            return {}
            
        try:
            # Get the node object if string or NodeId was passed
            if isinstance(node, str):
                node = self.client.get_node(node)
            elif isinstance(node, ua.NodeId):
                node = self.client.get_node(node)
                
            # Read all available attributes
            self.log("DEBUG", f"Reading attributes of node {node}")
            attrs = {}
            
            # Always read NodeId, NodeClass, BrowseName, and DisplayName
            attrs["NodeId"] = await node.read_node_id()
            attrs["NodeClass"] = await node.read_node_class()
            attrs["BrowseName"] = await node.read_browse_name()
            attrs["DisplayName"] = await node.read_display_name()
            
            # Read all other attributes (some might not be supported by the node)
            try:
                attrs["Description"] = await node.read_description()
            except:
                pass
                
            try:
                attrs["Value"] = await node.read_value()
            except:
                pass
                
            try:
                attrs["DataType"] = await node.read_data_type()
            except:
                pass
                
            try:
                attrs["ValueRank"] = await node.read_value_rank()
            except:
                pass
                
            try:
                attrs["AccessLevel"] = await node.read_attribute(ua.AttributeIds.AccessLevel)
            except:
                pass
                
            try:
                attrs["UserAccessLevel"] = await node.read_attribute(ua.AttributeIds.UserAccessLevel)
            except:
                pass
                
            try:
                attrs["Historizing"] = await node.read_attribute(ua.AttributeIds.Historizing)
            except:
                pass
                
            # Emit signal with results
            self.node_attributes_read.emit(node, attrs)
            return attrs
            
        except Exception as e:
            self.log("ERROR", f"Error reading node attributes {node}: {str(e)}")
            return {}
    
    async def read_node_references(self, node: Union[Node, str, ua.NodeId]) -> List[Dict[str, Any]]:
        """Read references of a node
        
        Args:
            node: Node to read references from (Node object, NodeId or string)
            
        Returns:
            List of references
        """
        if not self._check_connection():
            return []
            
        try:
            # Get the node object if string or NodeId was passed
            if isinstance(node, str):
                node = self.client.get_node(node)
            elif isinstance(node, ua.NodeId):
                node = self.client.get_node(node)
                
            # Read references
            self.log("DEBUG", f"Reading references of node {node}")
            references = await node.get_references()
            
            # Format references for display
            formatted_refs = []
            for ref in references:
                try:
                    target_node = self.client.get_node(ref.NodeId)
                    browse_name = await target_node.read_browse_name()
                    display_name = await target_node.read_display_name()
                    
                    formatted_refs.append({
                        "ReferenceTypeId": ref.ReferenceTypeId,
                        "NodeId": ref.NodeId,
                        "BrowseName": browse_name,
                        "DisplayName": display_name,
                        "IsForward": ref.IsForward,
                        "NodeClass": ref.NodeClass,
                    })
                except Exception as e:
                    self.log("WARNING", f"Error getting reference details: {e}")
                    formatted_refs.append({
                        "ReferenceTypeId": ref.ReferenceTypeId,
                        "NodeId": ref.NodeId,
                        "IsForward": ref.IsForward,
                        "NodeClass": ref.NodeClass,
                    })
            
            # Emit signal with results
            self.node_references_read.emit(node, formatted_refs)
            return formatted_refs
            
        except Exception as e:
            self.log("ERROR", f"Error reading node references {node}: {str(e)}")
            return []
    
    async def create_subscription(self, nodes: List[Union[Node, str, ua.NodeId]], interval: int = 1000, 
                                subscription_id: Optional[str] = None) -> Optional[str]:
        """Create a subscription for data changes
        
        Args:
            nodes: List of nodes to subscribe to
            interval: Subscription interval in milliseconds
            subscription_id: Optional subscription ID (generated if not provided)
            
        Returns:
            Subscription ID or None if error
        """
        if not self._check_connection():
            return None
            
        try:
            # Generate subscription ID if not provided
            if not subscription_id:
                subscription_id = f"sub_{int(time.time())}_{random.randint(1000, 9999)}"
                
            # Create handler for the subscription
            handler = DataChangeHandler(subscription_id)
            handler.data_change.connect(lambda sub_id, node, val, data: 
                                      self.subscription_data_change.emit(sub_id, node, val, data))
            handler.event.connect(lambda sub_id, event: 
                                self.subscription_event.emit(sub_id, event))
            
            # Create subscription
            self.log("INFO", f"Creating subscription {subscription_id} with interval {interval}ms")
            subscription = await self.client.create_subscription(interval, handler)
            
            # Store subscription for later use
            self.subscriptions[subscription_id] = (subscription, handler)
            
            # Subscribe to nodes
            node_handles = []
            for node_item in nodes:
                # Convert to Node object if needed
                if isinstance(node_item, str):
                    node = self.client.get_node(node_item)
                elif isinstance(node_item, ua.NodeId):
                    node = self.client.get_node(node_item)
                else:
                    node = node_item
                    
                # Subscribe to data changes
                try:
                    handle = await subscription.subscribe_data_change(node)
                    node_handles.append((node, handle))
                    self.log("DEBUG", f"Subscribed to node {node}")
                except Exception as e:
                    self.log("WARNING", f"Failed to subscribe to node {node}: {e}")
            
            # Emit signal with new subscription
            self.subscription_created.emit(subscription_id, subscription)
            return subscription_id
            
        except Exception as e:
            self.log("ERROR", f"Error creating subscription: {str(e)}")
            return None
    
    async def remove_subscription(self, subscription_id: str) -> bool:
        """Remove a subscription
        
        Args:
            subscription_id: Subscription ID to remove
            
        Returns:
            True if successful, False otherwise
        """
        if not self._check_connection():
            return False
            
        if subscription_id not in self.subscriptions:
            self.log("WARNING", f"Subscription {subscription_id} not found")
            return False
            
        try:
            # Get subscription
            subscription, handler = self.subscriptions[subscription_id]
            
            # Delete subscription from server
            self.log("INFO", f"Removing subscription {subscription_id}")
            await subscription.delete()
            
            # Remove from local storage
            self.subscriptions.pop(subscription_id)
            return True
            
        except Exception as e:
            self.log("ERROR", f"Error removing subscription {subscription_id}: {str(e)}")
            return False
    
    async def register_node(self, node: Union[Node, str, ua.NodeId], node_name: Optional[str] = None) -> Optional[str]:
        """Register a node for faster access
        
        Args:
            node: Node to register
            node_name: Optional name for the node (generated if not provided)
            
        Returns:
            Node registration ID or None if error
        """
        if not self._check_connection():
            return None
            
        try:
            # Convert to Node object if needed
            if isinstance(node, str):
                node_obj = self.client.get_node(node)
            elif isinstance(node, ua.NodeId):
                node_obj = self.client.get_node(node)
            else:
                node_obj = node
                
            # Generate node name if not provided
            if not node_name:
                try:
                    browse_name = await node_obj.read_browse_name()
                    node_name = browse_name.Name
                except:
                    node_id = await node_obj.read_node_id()
                    node_name = f"Node_{node_id.Identifier}"
                    
            # Make sure node_name is unique
            base_name = node_name
            counter = 1
            while node_name in self.registered_nodes:
                node_name = f"{base_name}_{counter}"
                counter += 1
                
            # Register node
            self.log("INFO", f"Registering node {node_obj} as '{node_name}'")
            
            # Store in local registry
            self.registered_nodes[node_name] = node_obj
            
            # Also store NodeId for saving to files
            node_id = await node_obj.read_node_id()
            self.registered_node_ids[node_name] = node_id
            
            # Emit signal for new registered node
            self.registered_node_added.emit(node_name, node_obj)
            return node_name
            
        except Exception as e:
            self.log("ERROR", f"Error registering node: {str(e)}")
            return None
    
    async def unregister_node(self, node_name: str) -> bool:
        """Unregister a node
        
        Args:
            node_name: Name of the node to unregister
            
        Returns:
            True if successful, False otherwise
        """
        if node_name not in self.registered_nodes:
            self.log("WARNING", f"Node '{node_name}' not registered")
            return False
            
        try:
            # Remove from registry
            self.log("INFO", f"Unregistering node '{node_name}'")
            self.registered_nodes.pop(node_name)
            self.registered_node_ids.pop(node_name, None)
            
            # Stop livebit task if running
            if node_name in self.livebit_tasks:
                task = self.livebit_tasks.pop(node_name)
                if not task.done():
                    task.cancel()
            
            # Emit signal for removed registered node
            self.registered_node_removed.emit(node_name)
            return True
            
        except Exception as e:
            self.log("ERROR", f"Error unregistering node '{node_name}': {str(e)}")
            return False
    
    async def start_livebit(self, node_name: str, interval: int = 5) -> bool:
        """Start LiveBit functionality for boolean nodes
        
        Args:
            node_name: Name of the registered node
            interval: Toggle interval in seconds
            
        Returns:
            True if successful, False otherwise
        """
        if not self._check_connection():
            return False
            
        if node_name not in self.registered_nodes:
            self.log("WARNING", f"Node '{node_name}' not registered")
            return False
            
        # Stop existing task if running
        if node_name in self.livebit_tasks:
            task = self.livebit_tasks.pop(node_name)
            if not task.done():
                task.cancel()
                
        try:
            # Create new task
            self.log("INFO", f"Starting LiveBit for node '{node_name}' with interval {interval}s")
            task = asyncio.create_task(self._livebit_task(node_name, interval))
            self.livebit_tasks[node_name] = task
            return True
            
        except Exception as e:
            self.log("ERROR", f"Error starting LiveBit for '{node_name}': {str(e)}")
            return False
    
    async def stop_livebit(self, node_name: str) -> bool:
        """Stop LiveBit functionality
        
        Args:
            node_name: Name of the registered node
            
        Returns:
            True if successful, False otherwise
        """
        if node_name not in self.livebit_tasks:
            self.log("WARNING", f"LiveBit not active for node '{node_name}'")
            return False
            
        try:
            # Cancel task
            self.log("INFO", f"Stopping LiveBit for node '{node_name}'")
            task = self.livebit_tasks.pop(node_name)
            if not task.done():
                task.cancel()
            return True
            
        except Exception as e:
            self.log("ERROR", f"Error stopping LiveBit for '{node_name}': {str(e)}")
            return False
    
    async def save_registered_nodes(self, directory: Union[str, Path]) -> bool:
        """Save registered nodes to JSON files
        
        Args:
            directory: Directory to save files to
            
        Returns:
            True if successful, False otherwise
        """
        directory = Path(directory)
        if not directory.exists():
            directory.mkdir(parents=True)
            
        saved_nodes = set()
        try:
            # Save each registered node to a file
            self.log("INFO", f"Saving {len(self.registered_nodes)} registered nodes to {directory}")
            
            for node_name, node_id in self.registered_node_ids.items():
                filename = directory / f"{node_name}.json"
                
                # Get current value if connected
                current_value = None
                if self.status == ConnectionStatus.CONNECTED and node_name in self.registered_nodes:
                    try:
                        node = self.registered_nodes[node_name]
                        data_value = await node.read_data_value()
                        if data_value.Value.is_numeric():
                            current_value = data_value.Value.Value
                        elif isinstance(data_value.Value.Value, (str, bool)):
                            current_value = data_value.Value.Value
                        elif data_value.Value.Value is not None:
                            current_value = str(data_value.Value.Value)
                    except Exception as e:
                        self.log("WARNING", f"Error reading value for node '{node_name}': {e}")
                
                # Save node information
                node_info = {
                    "name": node_name,
                    "node_id": str(node_id),
                    "namespace_index": node_id.NamespaceIndex,
                    "identifier_type": node_id.IdType.name,
                    "identifier": node_id.Identifier,
                    "last_value": current_value,
                    "last_updated": datetime.now().isoformat(),
                }
                
                with open(filename, 'w') as f:
                    json.dump(node_info, f, indent=4)
                    
                saved_nodes.add(node_name)
                
            # Clean up old node files that are no longer registered
            for file in directory.glob("*.json"):
                node_name = file.stem
                if node_name not in saved_nodes:
                    self.log("INFO", f"Removing old node file {file}")
                    file.unlink()
                    
            return True
            
        except Exception as e:
            self.log("ERROR", f"Error saving registered nodes: {str(e)}")
            return False
    
    async def load_registered_nodes(self, directory: Union[str, Path]) -> bool:
        """Load registered nodes from JSON files
        
        Args:
            directory: Directory to load files from
            
        Returns:
            True if successful, False otherwise
        """
        if not self._check_connection():
            return False
            
        directory = Path(directory)
        if not directory.exists():
            self.log("WARNING", f"Directory {directory} does not exist")
            return False
            
        try:
            # Load each node file
            self.log("INFO", f"Loading registered nodes from {directory}")
            
            for file in directory.glob("*.json"):
                try:
                    with open(file, 'r') as f:
                        node_info = json.load(f)
                        
                    node_name = node_info["name"]
                    node_id_str = node_info["node_id"]
                    
                    # Skip if already registered
                    if node_name in self.registered_nodes:
                        continue
                        
                    # Create node
                    node = self.client.get_node(node_id_str)
                    
                    # Register node
                    self.registered_nodes[node_name] = node
                    self.registered_node_ids[node_name] = await node.read_node_id()
                    
                    # Emit signal for new registered node
                    self.registered_node_added.emit(node_name, node)
                    
                except Exception as e:
                    self.log("WARNING", f"Error loading node from {file}: {e}")
                    
            return True
            
        except Exception as e:
            self.log("ERROR", f"Error loading registered nodes: {str(e)}")
            return False
    
    def _check_connection(self) -> bool:
        """Check if client is connected
        
        Returns:
            True if connected, False otherwise
        """
        if self.status != ConnectionStatus.CONNECTED or not self.client:
            self.log("WARNING", "Not connected to server")
            return False
        return True
    
    def _start_monitoring(self) -> None:
        """Start monitoring for connection issues"""
        if not self.client:
            return
            
        # Set connection lost callback
        async def on_connection_lost(exc):
            self.log("WARNING", f"Connection lost: {exc}")
            self.status = ConnectionStatus.DISCONNECTED
            self.connection_status_changed.emit(ConnectionStatus.DISCONNECTED, "Connection lost")
            self.connection_lost.emit(str(exc))
            
            # Attempt to reconnect if auto-reconnect is enabled
            if self.auto_reconnect:
                self._start_reconnect()
                
        self.client.connection_lost_callback = on_connection_lost
    
    def _start_reconnect(self) -> None:
        """Start reconnection attempts"""
        if self.reconnect_task and not self.reconnect_task.done():
            return
            
        self.reconnect_task = asyncio.create_task(self._reconnect_loop())
        
    async def _reconnect_loop(self) -> None:
        """Reconnection loop with exponential backoff"""
        self.reconnect_attempt = 0
        delay = self.initial_reconnect_delay
        
        while True:
            # Check if max attempts reached
            if self.max_reconnect_attempts > 0 and self.reconnect_attempt >= self.max_reconnect_attempts:
                self.log("WARNING", f"Max reconnection attempts ({self.max_reconnect_attempts}) reached")
                self.status = ConnectionStatus.ERROR
                self.connection_status_changed.emit(ConnectionStatus.ERROR, "Max reconnection attempts reached")
                return
                
            # Increment attempt counter
            self.reconnect_attempt += 1
            
            # Set status to connecting
            self.status = ConnectionStatus.CONNECTING
            self.connection_status_changed.emit(ConnectionStatus.CONNECTING, 
                                              f"Reconnecting (attempt {self.reconnect_attempt})...")
            
            # Attempt to reconnect
            try:
                self.log("INFO", f"Reconnecting to {self.endpoint_url} (attempt {self.reconnect_attempt})")
                
                # Create new client
                self.client = Client(self.endpoint_url)
                
                # Set security if needed
                if self.security_policy != "NO_SECURITY":
                    policy_class, mode = SECURITY_POLICY_MAP[self.security_policy]
                    if policy_class and self.certificate_path and self.private_key_path:
                        await self.client.set_security(
                            policy_class(),
                            self.certificate_path,
                            self.private_key_path,
                            mode=mode
                        )
                
                # Set user authentication if provided
                if self.username and self.password:
                    self.client.set_user(self.username)
                    self.client.set_password(self.password)
                
                # Connect to server
                await self.client.connect()
                
                # Update connection status
                self.status = ConnectionStatus.CONNECTED
                self.reconnect_attempt = 0
                self.connection_status_changed.emit(ConnectionStatus.CONNECTED, "Reconnected")
                self.connection_established.emit()
                
                # Set up monitoring for disconnection
                self._start_monitoring()
                
                self.log("INFO", f"Successfully reconnected to {self.endpoint_url}")
                
                # Reload registered nodes
                if self.registered_nodes:
                    # Temporarily clear registered nodes
                    old_registered_nodes = self.registered_node_ids.copy()
                    self.registered_nodes.clear()
                    self.registered_node_ids.clear()
                    
                    # Re-register nodes
                    for node_name, node_id in old_registered_nodes.items():
                        try:
                            node = self.client.get_node(node_id)
                            self.registered_nodes[node_name] = node
                            self.registered_node_ids[node_name] = node_id
                            self.registered_node_added.emit(node_name, node)
                        except Exception as e:
                            self.log("WARNING", f"Error re-registering node '{node_name}': {e}")
                
                # Success - exit reconnect loop
                return
                
            except Exception as e:
                error_msg = f"Reconnection attempt {self.reconnect_attempt} failed: {str(e)}"
                self.log("WARNING", error_msg)
                self.status = ConnectionStatus.ERROR
                self.connection_status_changed.emit(ConnectionStatus.ERROR, error_msg)
                
                # Calculate next delay with exponential backoff
                delay = min(delay * 1.5, self.max_reconnect_delay)
                self.log("INFO", f"Waiting {delay} seconds before next reconnection attempt")
                
                # Wait before next attempt
                try:
                    await asyncio.sleep(delay)
                except asyncio.CancelledError:
                    self.log("INFO", "Reconnection task cancelled")
                    return
    
    async def _livebit_task(self, node_name: str, interval: int) -> None:
        """LiveBit task that toggles a boolean value periodically"""
        if node_name not in self.registered_nodes:
            return
            
        node = self.registered_nodes[node_name]
        self.log("INFO", f"Starting LiveBit for node '{node_name}' with interval {interval}s")
        
        try:
            while True:
                try:
                    # Read current value
                    data_value = await node.read_data_value()
                    
                    # Only toggle if it's a boolean
                    if data_value.Value.is_boolean():
                        current_value = data_value.Value.Value
                        new_value = not current_value
                        
                        # Write new value
                        self.log("DEBUG", f"LiveBit toggling node '{node_name}' from {current_value} to {new_value}")
                        await node.write_value(new_value)
                    else:
                        self.log("WARNING", f"LiveBit: Node '{node_name}' is not a boolean, stopping LiveBit")
                        return
                        
                except asyncio.CancelledError:
                    self.log("INFO", f"LiveBit for node '{node_name}' cancelled")
                    return
                except Exception as e:
                    self.log("WARNING", f"Error in LiveBit for node '{node_name}': {e}")
                    
                # Wait for next toggle
                await asyncio.sleep(interval)
                
        except asyncio.CancelledError:
            self.log("INFO", f"LiveBit for node '{node_name}' cancelled")
            return
        except Exception as e:
            self.log("ERROR", f"LiveBit for node '{node_name}' failed: {e}")
import os
import asyncio
import random
import json
from json_output_manager import JsonOutputManager
from typing import Dict, Any, Optional, List, Tuple, Callable, Union, Set
from datetime import datetime
from enum import Enum
import time

from asyncua import Client, Node, ua
from asyncua.crypto import security_policies

from PyQt5.QtCore import QObject, QThread, pyqtSignal, QTimer

from config_manager import Config, SecurityPolicy

from utils import get_logger, ConnectionStatus
from extension_objects import ExtensionObjectManager

logger = get_logger("client_core")

# Map SecurityPolicy enum to actual security policy classes and message security modes
SECURITY_POLICY_MAP = {
    SecurityPolicy.NO_SECURITY: (None, ua.MessageSecurityMode.None_),
    SecurityPolicy.BASIC128RSA15_SIGN: (security_policies.SecurityPolicyBasic128Rsa15, ua.MessageSecurityMode.Sign),
    SecurityPolicy.BASIC128RSA15_SIGN_ENCRYPT: (security_policies.SecurityPolicyBasic128Rsa15, ua.MessageSecurityMode.SignAndEncrypt),
    SecurityPolicy.BASIC256_SIGN: (security_policies.SecurityPolicyBasic256, ua.MessageSecurityMode.Sign),
    SecurityPolicy.BASIC256_SIGN_ENCRYPT: (security_policies.SecurityPolicyBasic256, ua.MessageSecurityMode.SignAndEncrypt),
    SecurityPolicy.BASIC256SHA256_SIGN: (security_policies.SecurityPolicyBasic256Sha256, ua.MessageSecurityMode.Sign),
    SecurityPolicy.BASIC256SHA256_SIGN_ENCRYPT: (security_policies.SecurityPolicyBasic256Sha256, ua.MessageSecurityMode.SignAndEncrypt),
    SecurityPolicy.AES128SHA256RSAOAEP_SIGN: (security_policies.SecurityPolicyAes128Sha256RsaOaep, ua.MessageSecurityMode.Sign),
    SecurityPolicy.AES128SHA256RSAOAEP_SIGN_ENCRYPT: (security_policies.SecurityPolicyAes128Sha256RsaOaep, ua.MessageSecurityMode.SignAndEncrypt),
    SecurityPolicy.AES256SHA256RSAPSS_SIGN: (security_policies.SecurityPolicyAes256Sha256RsaPss, ua.MessageSecurityMode.Sign),
    SecurityPolicy.AES256SHA256RSAPSS_SIGN_ENCRYPT: (security_policies.SecurityPolicyAes256Sha256RsaPss, ua.MessageSecurityMode.SignAndEncrypt),
}

class OpcUaClient(QObject):
    """Core OPC UA Client implementation using asyncua library"""
    
    # Signal definitions
    connection_status_changed = pyqtSignal(ConnectionStatus, str)
    nodes_browsed = pyqtSignal(list, str)  # nodes, parent_id
    node_details_available = pyqtSignal(dict)
    node_subscribed = pyqtSignal(str, str, object)  # node_id, display_name, initial_value
    node_unsubscribed = pyqtSignal(str)  # node_id
    subscription_data_changed = pyqtSignal(str, object, str)  # node_id, value, timestamp
    json_updated = pyqtSignal(str)  # filename
    reconnection_status = pyqtSignal(int, int, str)  # attempts, max_attempts, message
    method_called = pyqtSignal(str, bool, str)  # method_id, success, result
    node_registered = pyqtSignal(str, str, str, object)  # node_id, display_name, data_type, initial_value
    node_write_completed = pyqtSignal(str, bool, str)  # node_id, success, message
    
    def __init__(self, config: Config, parent=None):
        """Initialize OPC UA Client"""
        super().__init__(parent)
        self.config = config
        self.client = None
        self.connected = False
        self.reconnecting = False
        self.reconnect_attempts = 0
        
        self.subscription = None
        self.subscription_handles = {}  # Dict[node_id, (handle, display_name)]
        self.registered_nodes = {}  # Dict[node_id, node_info]
        
        self.connection_start_time = None
        self.connection_diagnostics = {}
        
        os.makedirs(self.config.json_output_dir, exist_ok=True)

        # For JSON output with JSON
        self.json_output_manager = JsonOutputManager(self.config.json_output_dir)
        
        self.json_output_manager.json_updated.connect(self.on_json_updated)
        # Connect write requested signal
        self.json_output_manager.write_requested.connect(self.on_write_requested)
        
        # Extension object manager
        self.extension_object_manager = ExtensionObjectManager()
        
        # Livebits for registered nodes
        self.livebit_nodes = {}  # Dict[node_id, toggle_interval]
        self.last_toggle_time = {}  # Dict[node_id, last_toggle_time]
        self.livebit_timer = QTimer(self)
        self.livebit_timer.timeout.connect(self.process_livebit_nodes)
        self.livebit_timer.start(100)  # Check every 100ms
        
        # Remove the old custom node check timer - it's now handled by file watcher
        # self.custom_node_check_timer = QTimer(self)
        # self.custom_node_check_timer.timeout.connect(self.check_custom_node_writes)
        # self.custom_node_check_timer.start(1000)  # Check every second
        
        # Worker thread for async operations
        self.worker_thread = None
        self.loop = None
    
    def on_write_requested(self, node_id: str, value: Any):
        """Handle write request from file watcher"""
        if not self.connected or not self.client:
            logger.warning(f"Cannot write to {node_id}: not connected")
            self.json_output_manager.mark_write_completed(node_id, False)
            return
        
        logger.info(f"Write requested for node {node_id} with value {value}")
        
        # Schedule the write operation
        if self.loop:
            asyncio.run_coroutine_threadsafe(
                self._handle_write_request(node_id, value),
                self.loop
            )

    async def _handle_write_request(self, node_id: str, value: Any):
        """Handle write request asynchronously"""
        try:
            success, message = await self.write_value(node_id, value, False)
            
            if success:
                logger.info(f"Successfully wrote value to node {node_id}: {value}")
                
                # Update the JSON file with the actual written value
                # This ensures the file reflects the current OPC UA value
                if node_id in self.registered_nodes:
                    self.registered_nodes[node_id]["last_value"] = value
                    
                    # Update JSON output - this will update the file
                    self.json_output_manager.update_registered_node_value(node_id, value)
                
            else:
                logger.error(f"Failed to write value to node {node_id}: {message}")
            
            # Notify JSON output manager of completion
            self.json_output_manager.mark_write_completed(node_id, success)
            
        except Exception as e:
            logger.error(f"Error in write request handler for node {node_id}: {str(e)}")
            self.json_output_manager.mark_write_completed(node_id, False)
    
    
    def start(self):
        """Start the client worker thread"""
        if self.worker_thread is not None and self.worker_thread.isRunning():
            logger.warning("Worker thread already running")
            return
        
        # Create and start worker thread
        self.worker_thread = QThread()
        self.moveToThread(self.worker_thread)
        
        # Connect thread signals
        self.worker_thread.started.connect(self.run)
        self.worker_thread.finished.connect(self.on_thread_finished)
        
        # Start thread
        self.worker_thread.start()
        
        logger.info("Worker thread started")
    
    def stop(self):
        """Stop the client worker thread"""
        if self.worker_thread is None or not self.worker_thread.isRunning():
            logger.warning("Worker thread not running")
            return
        
        # Schedule disconnect if connected
        if self.connected and self.client:
            if self.loop:
                asyncio.run_coroutine_threadsafe(self.disconnect(), self.loop)
        
        # Stop thread
        self.worker_thread.quit()
        self.worker_thread.wait(5000)  # Wait up to 5 seconds
        
        if self.worker_thread.isRunning():
            logger.warning("Worker thread did not quit, terminating")
            self.worker_thread.terminate()
        
        logger.info("Worker thread stopped")
    
    def on_thread_finished(self):
        """Handle worker thread finished signal"""
        logger.info("Worker thread finished")
    
    def run(self):
        """Main worker thread run method"""
        # Create new event loop for this thread
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        
        # Run client main loop
        try:
            self.loop.run_until_complete(self.main_loop())
        except Exception as e:
            logger.error(f"Error in main loop: {str(e)}")
        finally:
            # Clean up
            self.loop.close()
            self.loop = None
    
    async def main_loop(self):
        """Main asynchronous loop"""
        # Auto-connect if configured
        if self.config.auto_connect:
            await self.connect()
        
        # Keep thread alive until stopped
        while self.worker_thread.isRunning():
            try:
                # Check connection status
                if self.connected and self.client:
                    try:
                        # Ping server by reading server time
                        await self.client.nodes.server_state.read_value()
                    except Exception as e:
                        logger.warning(f"Connection check failed: {str(e)}")
                        if self.connected:
                            await self.handle_connection_lost(e)
                
                # Sleep to avoid high CPU usage
                await asyncio.sleep(1)
            
            except Exception as e:
                logger.error(f"Error in main loop iteration: {str(e)}")
                await asyncio.sleep(1)
    
    async def connect(self):
        """Connect to OPC UA server"""
        if self.connected:
            logger.warning("Already connected, disconnecting first")
            await self.disconnect()
        
        # Record connection start time
        self.connection_start_time = time.time()
        self.connection_diagnostics = {
            "status": "connecting",
            "start_time": self.connection_start_time,
            "endpoint": self.config.endpoint,
            "security_policy": self.config.security_policy.value,
            "steps": []
        }
        
        # Update connection status
        self.connection_status_changed.emit(
            ConnectionStatus.CONNECTING, 
            f"Connecting to {self.config.endpoint}..."
        )
        
        try:
            # Create client
            self._log_connection_step("Creating client")
            self.client = Client(url=self.config.endpoint)
            
            # Set up connection lost callback
            self.client.connection_lost_callback = self.handle_connection_lost
            
            # Configure security if needed
            if self.config.security_policy != SecurityPolicy.NO_SECURITY:
                # Set application URI
                application_uri = self.config.certificate_info.get("application_uri")
                if not application_uri:
                    import socket
                    hostname = socket.gethostname()
                    org_name = self.config.certificate_info["organization"].lower().replace(' ', '')
                    application_uri = f"urn:{org_name}:{hostname}:opcuaclient"
                    self.config.certificate_info["application_uri"] = application_uri
                
                self._log_connection_step(f"Setting application URI: {application_uri}")
                self.client.application_uri = application_uri
                self.client.name = "OPC UA Client"
                
                # Set security policy
                policy, mode = SECURITY_POLICY_MAP[self.config.security_policy]
                if policy:
                    self._log_connection_step(f"Setting security policy: {self.config.security_policy.value}")
                    await self.client.set_security(
                        policy,
                        self.config.certificate_path,
                        self.config.private_key_path,
                        mode=mode
                    )
            
            # Set authentication if provided
            if self.config.username:
                password = self.config.load_password()
                if password:
                    self._log_connection_step(f"Setting authentication for user: {self.config.username}")
                    self.client.set_user(self.config.username)
                    self.client.set_password(password)
                else:
                    logger.warning(f"No password found for user {self.config.username}")
            
            # Connect to server
            self._log_connection_step("Connecting to server")
            await self.client.connect()
            
            # Load data type dictionaries to support extension objects
            self._log_connection_step("Loading data type dictionaries")
            await self.extension_object_manager.load_data_types(self.client)
            
            # Record successful connection
            connection_time = time.time() - self.connection_start_time
            self.connection_diagnostics["status"] = "connected"
            self.connection_diagnostics["connection_time"] = connection_time
            self._log_connection_step(f"Connected successfully in {connection_time:.2f} seconds")
            
            # Update connection status
            self.connected = True
            self.connection_status_changed.emit(
                ConnectionStatus.CONNECTED, 
                f"Connected to {self.config.endpoint}"
            )
            
            # Reset reconnection attempts
            if self.reconnecting:
                logger.info(f"Reconnection successful after {self.reconnect_attempts} attempts")
                self.reconnection_status.emit(
                    self.reconnect_attempts, 
                    self.config.max_reconnect_attempts,
                    "Connection restored"
                )
                self.reconnecting = False
            self.reconnect_attempts = 0
            
            # Restore subscriptions
            await self.restore_subscriptions()
            
            # Create new subscription if not exists
            if not self.subscription and (self.config.subscribed_nodes or self.config.registered_nodes):
                self._log_connection_step("Creating subscription")
                self.subscription = await self.client.create_subscription(500, self)
            
            # Subscribe to nodes
            for node_id, display_name in self.config.subscribed_nodes.items():
                await self.subscribe_to_node(node_id, display_name)
            
            # Register nodes
            for node_id, node_info in self.config.registered_nodes.items():
                await self.register_node(node_id, node_info)
            
            return True
        
        except Exception as e:
            error_msg = f"Connection error: {str(e)}"
            logger.error(error_msg)
            
            # Update diagnostics
            self.connection_diagnostics["status"] = "failed"
            self.connection_diagnostics["error"] = str(e)
            self.connection_diagnostics["connection_time"] = time.time() - self.connection_start_time
            self._log_connection_step(f"Connection failed: {str(e)}")
            
            # Update connection status
            if not self.reconnecting:
                self.connection_status_changed.emit(
                    ConnectionStatus.ERROR, 
                    error_msg
                )
            
            # Start reconnection if enabled
            if self.config.auto_reconnect and not self.reconnecting:
                await self.start_reconnection()
            
            return False
    
    async def disconnect(self):
        """Disconnect from OPC UA server"""
        if not self.connected or not self.client:
            logger.warning("Not connected")
            return
        
        try:
            logger.info("Disconnecting from server")
            
            # Delete subscription
            if self.subscription:
                try:
                    await self.subscription.delete()
                except Exception as e:
                    logger.warning(f"Error deleting subscription: {str(e)}")
                finally:
                    self.subscription = None
                    self.subscription_handles.clear()
            
            # Disconnect client
            await self.client.disconnect()
            
            # Update status
            self.connected = False
            self.connection_status_changed.emit(
                ConnectionStatus.DISCONNECTED, 
                "Disconnected from server"
            )
            
            logger.info("Disconnected from server")
        
        except Exception as e:
            error_msg = f"Error during disconnect: {str(e)}"
            logger.error(error_msg)
            
            # Force disconnect
            self.connected = False
            self.connection_status_changed.emit(
                ConnectionStatus.ERROR, 
                error_msg
            )
    
    def _log_connection_step(self, message: str):
        """
        Log a connection step for diagnostics
        
        Args:
            message: Step message
        """
        if self.connection_start_time:
            step_time = time.time() - self.connection_start_time
            step = {
                "time": step_time,
                "message": message
            }
            if "steps" in self.connection_diagnostics:
                self.connection_diagnostics["steps"].append(step)
            logger.info(f"[{step_time:.2f}s] {message}")
        else:
            logger.info(message)
    
    async def handle_connection_lost(self, exception):
        """
        Handle connection lost event
        
        Args:
            exception: Exception that caused the connection loss
        """
        if not self.connected:
            return  # Already disconnected
        
        logger.warning(f"Connection lost: {str(exception)}")
        self.connected = False
        
        # Notify about connection loss
        self.connection_status_changed.emit(
            ConnectionStatus.DISCONNECTED, 
            f"Connection lost: {str(exception)}"
        )
        
        # Start reconnection if enabled
        if self.config.auto_reconnect:
            await self.start_reconnection()
    
    async def start_reconnection(self):
        """Start the reconnection process"""
        if self.reconnecting:
            return  # Already reconnecting
        
        self.reconnecting = True
        self.reconnect_attempts = 0
        
        logger.info("Starting reconnection process")
        self.connection_status_changed.emit(
            ConnectionStatus.RECONNECTING, 
            "Connection lost. Attempting to reconnect..."
        )
        
        # Schedule first reconnection attempt
        await self.attempt_reconnect()
    
    async def attempt_reconnect(self):
        """Attempt to reconnect with exponential backoff"""
        if not self.reconnecting:
            return  # Reconnection was cancelled
        
        # Check max attempts
        max_attempts = self.config.max_reconnect_attempts
        if max_attempts > 0 and self.reconnect_attempts >= max_attempts:
            logger.error(f"Maximum reconnection attempts ({max_attempts}) reached")
            self.reconnecting = False
            self.connection_status_changed.emit(
                ConnectionStatus.ERROR, 
                f"Reconnection failed after {max_attempts} attempts"
            )
            self.reconnection_status.emit(
                self.reconnect_attempts, 
                max_attempts, 
                "Maximum attempts reached"
            )
            return
        
        # Calculate backoff time
        delay = min(
            self.config.reconnect_delay * (2 ** min(self.reconnect_attempts, 8)),
            self.config.max_reconnect_delay
        )
        
        # Add jitter (±10%)
        jitter = delay * 0.1
        backoff = delay + random.uniform(-jitter, jitter)
        
        # Update attempts counter
        self.reconnect_attempts += 1
        
        # Notify about reconnection attempt
        status_msg = f"Reconnection attempt {self.reconnect_attempts}"
        if max_attempts > 0:
            status_msg += f" of {max_attempts}"
        status_msg += f" in {backoff:.1f} seconds..."
        
        self.connection_status_changed.emit(
            ConnectionStatus.RECONNECTING, 
            status_msg
        )
        
        self.reconnection_status.emit(
            self.reconnect_attempts, 
            max_attempts, 
            f"Waiting {backoff:.1f} seconds"
        )
        
        # Wait before reconnecting
        logger.info(f"Waiting {backoff:.1f} seconds before reconnection attempt {self.reconnect_attempts}")
        await asyncio.sleep(backoff)
        
        # Check if still reconnecting
        if not self.reconnecting:
            return  # Reconnection was cancelled during sleep
        
        # Attempt reconnection
        logger.info(f"Attempting to reconnect (attempt {self.reconnect_attempts})")
        self.connection_status_changed.emit(
            ConnectionStatus.RECONNECTING, 
            f"Reconnecting... (attempt {self.reconnect_attempts})"
        )
        
        self.reconnection_status.emit(
            self.reconnect_attempts, 
            max_attempts, 
            "Connecting..."
        )
        
        # Connect
        success = await self.connect()
        
        # If failed, schedule next attempt
        if not success:
            await self.attempt_reconnect()
    
    async def restore_subscriptions(self):
        """Restore subscriptions after reconnection"""
        if not self.connected or not self.client:
            return
        
        logger.info("Restoring subscriptions")
        
        # Create subscription if needed
        if not self.subscription and (self.config.subscribed_nodes or self.config.registered_nodes):
            try:
                self.subscription = await self.client.create_subscription(500, self)
            except Exception as e:
                logger.error(f"Error creating subscription: {str(e)}")
                return
        
        # Clear current handles
        self.subscription_handles.clear()
        
        # Clear LiveBit settings
        self.livebit_nodes.clear()
        self.last_toggle_time.clear()
        
        # Restore subscriptions
        for node_id, display_name in self.config.subscribed_nodes.items():
            await self.subscribe_to_node(node_id, display_name)
        
        # Restore registered nodes
        for node_id, node_info in self.config.registered_nodes.items():
            # Make a copy of node_info to avoid modifying the original
            node_info_copy = node_info.copy()
            
            logger.info(f"Restoring registered node: {node_id} with type {node_info_copy.get('node_type', 'Standard')}")
            
            # Ensure we're preserving the node_type
            if node_info_copy.get("node_type") == "LiveBit":
                # Make sure we set up LiveBit functionality before registering
                if "data_type" in node_info_copy and node_info_copy.get("data_type") == "Boolean":
                    logger.info(f"Setting up LiveBit for node {node_id} with interval {node_info_copy.get('toggle_interval', 1.0)}")
            
            # Register the node with the original settings
            await self.register_node(node_id, node_info_copy)
        
        logger.info("Subscriptions restored")
    
    async def get_node_details(self, node_id: str):
        """
        Get detailed information about a node
        
        Args:
            node_id: Node ID
        """
        if not self.connected or not self.client:
            return
        
        try:
            logger.info(f"Getting details for node: {node_id}")
            node = self.client.get_node(node_id)
            
            # Get attributes
            attributes = {}
            try:
                attributes["NodeId"] = node_id
                attributes["BrowseName"] = (await node.read_browse_name()).Name
                attributes["DisplayName"] = (await node.read_display_name()).Text
                node_class = await node.read_node_class()
                attributes["NodeClass"] = node_class.name
                
                # Get data type and value for variables
                if node_class == ua.NodeClass.Variable:
                    try:
                        data_type_node = await node.read_data_type()
                        data_type = await self.client.get_node(data_type_node).read_browse_name()
                        attributes["DataType"] = data_type.Name
                        
                        # Get value rank (dimensionality)
                        value_rank = await node.read_value_rank()
                        if value_rank == ua.ValueRank.Scalar:
                            attributes["ValueRank"] = "Scalar"
                        elif value_rank == ua.ValueRank.OneDimension:
                            attributes["ValueRank"] = "OneDimension"
                        elif value_rank == ua.ValueRank.OneOrMoreDimensions:
                            attributes["ValueRank"] = "OneOrMoreDimensions"
                        elif value_rank == ua.ValueRank.Any:
                            attributes["ValueRank"] = "Any"
                        else:
                            attributes["ValueRank"] = str(value_rank)
                        
                        # Check if this might be an extension object
                        is_extension_object = data_type.Name in [
                            "ExtensionObject", "Structure"
                        ] or await self.extension_object_manager.is_extension_object(self.client, data_type_node)
                        
                        if is_extension_object:
                            attributes["DataType"] = f"ExtensionObject ({data_type.Name})"
                            
                            # Get extension object type info
                            try:
                                type_info = await self.extension_object_manager.get_extension_object_type_info(
                                    self.client, data_type_node
                                )
                                if type_info:
                                    attributes["ExtensionObjectInfo"] = type_info
                            except Exception as e:
                                logger.warning(f"Error getting extension object type info: {str(e)}")
                        
                        # Get current value
                        try:
                            value = await node.read_value()
                            
                            # Handle extension objects
                            if is_extension_object and value is not None:
                                decoded = await self.extension_object_manager.decode_extension_object(value)
                                if decoded:
                                    attributes["Value"] = str(decoded)
                                else:
                                    attributes["Value"] = str(value)
                            else:
                                attributes["Value"] = str(value)
                        except Exception as e:
                            attributes["Value"] = f"Error reading value: {str(e)}"
                        
                        # Get access level
                        try:
                            access_level = await node.read_attribute(ua.AttributeIds.AccessLevel)
                            access_level_value = access_level.Value.Value
                            attributes["AccessLevel"] = str(ua.AccessLevel(access_level_value))
                            attributes["Writable"] = bool(access_level_value & ua.AccessLevel.CurrentWrite)
                        except Exception:
                            attributes["AccessLevel"] = "Unknown"
                            attributes["Writable"] = False
                    except Exception as e:
                        logger.error(f"Error reading variable details: {str(e)}")
                
                # Get description
                try:
                    description = await node.read_attribute(ua.AttributeIds.Description)
                    if description.Value.Value:
                        attributes["Description"] = description.Value.Value.Text
                except Exception:
                    pass
                
                # For method nodes, get input and output arguments
                if node_class == ua.NodeClass.Method:
                    try:
                        # Try to get method details using references
                        input_args = []
                        output_args = []
                        
                        # Get references to find input and output arguments
                        refs = await node.get_children_descriptions(refs=ua.ObjectIds.HasProperty)
                        
                        for ref in refs:
                            if ref.BrowseName.Name == "InputArguments":
                                input_arg_node = self.client.get_node(ref.NodeId)
                                input_args_value = await input_arg_node.read_value()
                                for arg in input_args_value:
                                    input_args.append({
                                        "Name": arg.Name,
                                        "Type": arg.DataType.to_string(),
                                        "Description": arg.Description.Text if arg.Description else ""
                                    })
                            elif ref.BrowseName.Name == "OutputArguments":
                                output_arg_node = self.client.get_node(ref.NodeId)
                                output_args_value = await output_arg_node.read_value()
                                for arg in output_args_value:
                                    output_args.append({
                                        "Name": arg.Name,
                                        "Type": arg.DataType.to_string(),
                                        "Description": arg.Description.Text if arg.Description else ""
                                    })
                        
                        if input_args:
                            attributes["InputArguments"] = input_args
                        if output_args:
                            attributes["OutputArguments"] = output_args
                    except Exception as e:
                        logger.error(f"Error reading method details: {str(e)}")
            except Exception as e:
                logger.error(f"Error reading attributes: {str(e)}")
            
            # Get references
            references = []
            try:
                refs = await node.get_references()
                for ref in refs:
                    try:
                        target_node = self.client.get_node(ref.NodeId)
                        target_name = (await target_node.read_display_name()).Text
                        ref_type_node = self.client.get_node(ref.ReferenceTypeId)
                        ref_type_name = (await ref_type_node.read_browse_name()).Name
                        
                        # Add direction indicator
                        direction = "→" if ref.IsForward else "←"
                        ref_display = f"{ref_type_name} {direction}"
                        
                        references.append({
                            "ReferenceType": ref_type_name,
                            "Direction": "Forward" if ref.IsForward else "Inverse",
                            "DisplayName": target_name,
                            "NodeId": ref.NodeId.to_string(),
                            "Display": f"{ref_display}: {target_name}"
                        })
                    except Exception as e:
                        logger.error(f"Error processing reference: {str(e)}")
            except Exception as e:
                logger.error(f"Error getting references: {str(e)}")
            
            # Sort references by display
            references.sort(key=lambda x: x["Display"])
            
            # Emit details
            details = {
                "node_id": node_id,
                "attributes": attributes,
                "references": references
            }
            
            self.node_details_available.emit(details)
            
        except Exception as e:
            error_msg = f"Error getting node details: {str(e)}"
            logger.error(error_msg)

    async def browse_nodes(self, parent_node_id: Optional[str] = None):
        """
        Browse nodes from the specified parent node
        
        Args:
            parent_node_id: Parent node ID (None for root)
        """
        if not self.connected or not self.client:
            self.connection_status_changed.emit(
                ConnectionStatus.ERROR, 
                "Not connected to server"
            )
            return
        
        try:
            logger.info(f"Browsing nodes under parent: {parent_node_id}")
            
            # Special case for Root node (i=84) - ensure standard folders
            if parent_node_id == "i=84":  # Root node
                nodes = [
                    {
                        'id': 'i=85',
                        'browse_name': 'Objects',
                        'display_name': 'Objects',
                        'node_class': 'Object',
                        'has_children': True,
                        'parent_id': parent_node_id,
                        'data_type': None
                    },
                    {
                        'id': 'i=86',
                        'browse_name': 'Types',
                        'display_name': 'Types',
                        'node_class': 'Object',
                        'has_children': True,
                        'parent_id': parent_node_id,
                        'data_type': None
                    },
                    {
                        'id': 'i=87',
                        'browse_name': 'Views',
                        'display_name': 'Views',
                        'node_class': 'Object',
                        'has_children': True,
                        'parent_id': parent_node_id,
                        'data_type': None
                    }
                ]
                
                # Emit nodes browsed signal
                self.nodes_browsed.emit(nodes, parent_node_id)
                return
            
            # Special case for Types node (i=86) - ensure standard type categories
            if parent_node_id == "i=86":  # Types node
                nodes = [
                    {
                        'id': 'i=88',
                        'browse_name': 'ObjectTypes',
                        'display_name': 'ObjectTypes',
                        'node_class': 'Object',
                        'has_children': True,
                        'parent_id': parent_node_id,
                        'data_type': None
                    },
                    {
                        'id': 'i=89',
                        'browse_name': 'VariableTypes',
                        'display_name': 'VariableTypes',
                        'node_class': 'Object',
                        'has_children': True,
                        'parent_id': parent_node_id,
                        'data_type': None
                    },
                    {
                        'id': 'i=90',
                        'browse_name': 'ReferenceTypes',
                        'display_name': 'ReferenceTypes',
                        'node_class': 'Object',
                        'has_children': True,
                        'parent_id': parent_node_id,
                        'data_type': None
                    },
                    {
                        'id': 'i=91',
                        'browse_name': 'DataTypes',
                        'display_name': 'DataTypes',
                        'node_class': 'Object',
                        'has_children': True,
                        'parent_id': parent_node_id,
                        'data_type': None
                    },
                    {
                        'id': 'i=92',
                        'browse_name': 'EventTypes',
                        'display_name': 'EventTypes',
                        'node_class': 'Object',
                        'has_children': True,
                        'parent_id': parent_node_id,
                        'data_type': None
                    }
                ]
                
                # Emit nodes browsed signal
                self.nodes_browsed.emit(nodes, parent_node_id)
                return
                
            # Get parent node
            if parent_node_id:
                parent_node = self.client.get_node(parent_node_id)
            else:
                # Start from Objects folder
                parent_node = self.client.nodes.objects
            
            # Use browse method to reduce duplicates
            nodes = []
            try:
                desc = ua.BrowseDescription()
                desc.NodeId = parent_node.nodeid
                desc.BrowseDirection = ua.BrowseDirection.Forward
                desc.ReferenceTypeId = ua.NodeId(ua.ObjectIds.HierarchicalReferences)
                desc.IncludeSubtypes = True
                desc.NodeClassMask = ua.NodeClass.Object | ua.NodeClass.Variable | ua.NodeClass.Method
                desc.ResultMask = ua.BrowseResultMask.All
                
                params = ua.BrowseParameters()
                params.View = ua.ViewDescription()
                params.RequestedMaxReferencesPerNode = 0
                params.NodesToBrowse = [desc]
                
                # Use the correct method for browsing
                results = await self.client.uaclient.browse(params)
                
                if results and len(results) > 0 and results[0].References:
                    for ref in results[0].References:
                        try:
                            node_id = ref.NodeId.to_string()
                            display_name = ref.DisplayName.Text
                            browse_name = ref.BrowseName.Name
                            node_class = ua.NodeClass(ref.NodeClass).name
                            
                            # Determine if the node has children
                            has_children = True  # Assume it has children to allow expansion
                            if ref.NodeClass == ua.NodeClass.Variable:
                                # Variables typically don't have children
                                has_children = False
                            
                            # Get data type for variables
                            data_type = None
                            data_type_id = None
                            if ref.NodeClass == ua.NodeClass.Variable:
                                try:
                                    node = self.client.get_node(node_id)
                                    data_type_node = await node.read_data_type()
                                    data_type_id = data_type_node.to_string()
                                    data_type_name = await self.client.get_node(data_type_node).read_browse_name()
                                    data_type = data_type_name.Name
                                    
                                    # Check if this is an extension object
                                    is_extension = data_type in ["ExtensionObject", "Structure"] or \
                                        await self.extension_object_manager.is_extension_object(self.client, data_type_node)
                                    
                                    if is_extension:
                                        data_type = f"ExtensionObject ({data_type})"
                                except Exception:
                                    data_type = "Unknown"
                            
                            nodes.append({
                                'id': node_id,
                                'browse_name': browse_name,
                                'display_name': display_name,
                                'node_class': node_class,
                                'has_children': has_children,
                                'parent_id': parent_node_id,
                                'data_type': data_type,
                                'data_type_id': data_type_id
                            })
                        except Exception as e:
                            logger.error(f"Error processing reference: {str(e)}")
            except Exception as e:
                logger.warning(f"Error using browse method: {str(e)}")
            
            # If primary method failed, try fallback method
            if not nodes:
                try:
                    children = await parent_node.get_children()
                    
                    for node in children:
                        try:
                            node_id = node.nodeid.to_string()
                            browse_name = await node.read_browse_name()
                            display_name = await node.read_display_name()
                            node_class = await node.read_node_class()
                            
                            # Get data type for variables
                            data_type = None
                            data_type_id = None
                            if node_class == ua.NodeClass.Variable:
                                try:
                                    data_type_node = await node.read_data_type()
                                    data_type_id = data_type_node.to_string()
                                    data_type_name = await self.client.get_node(data_type_node).read_browse_name()
                                    data_type = data_type_name.Name
                                    
                                    # Check if this is an extension object
                                    is_extension = data_type in ["ExtensionObject", "Structure"] or \
                                        await self.extension_object_manager.is_extension_object(self.client, data_type_node)
                                    
                                    if is_extension:
                                        data_type = f"ExtensionObject ({data_type})"
                                except Exception:
                                    data_type = "Unknown"
                            
                            nodes.append({
                                'id': node_id,
                                'browse_name': browse_name.Name,
                                'display_name': display_name.Text,
                                'node_class': node_class.name,
                                'has_children': node_class != ua.NodeClass.Variable,
                                'parent_id': parent_node_id,
                                'data_type': data_type,
                                'data_type_id': data_type_id
                            })
                        except Exception as e:
                            logger.error(f"Error reading node details: {str(e)}")
                except Exception as e:
                    logger.warning(f"Error using fallback method: {str(e)}")
            
            # If still no nodes, add placeholder
            if not nodes:
                nodes.append({
                    'id': '',
                    'browse_name': 'No nodes found',
                    'display_name': 'No nodes found',
                    'node_class': '',
                    'has_children': False,
                    'parent_id': parent_node_id,
                    'data_type': None,
                    'data_type_id': None
                })
            
            # Sort nodes by display name
            nodes.sort(key=lambda x: x['display_name'])
            
            # Emit nodes browsed signal
            self.nodes_browsed.emit(nodes, parent_node_id)
            
        except Exception as e:
            error_msg = f"Error browsing nodes: {str(e)}"
            logger.error(error_msg)
            self.connection_status_changed.emit(
                ConnectionStatus.ERROR, 
                error_msg
            )
    
    def get_node_structure_info(self, node_id: str) -> dict:
        """
        Get structure information for a node
        
        Args:
            node_id: Node ID
            
        Returns:
            Dictionary with structure information
        """
        structure_info = {
            "parent_path": "",
            "node_class": "Unknown",
            "display_name": "Unknown"
        }
        
        if not self.connected or not self.client:
            return structure_info
        
        try:
            node = self.client.get_node(node_id)
            
            # Get display name
            display_name = node.read_display_name()
            structure_info["display_name"] = display_name.Text
            
            # Get node class
            node_class = node.read_node_class()
            structure_info["node_class"] = node_class.name
            
            # Get parent path by traversing up the hierarchy
            parent_path = []
            current_node = node
            
            try:
                while True:
                    # Get parent references
                    parent_refs = current_node.get_references(refs=ua.ObjectIds.HierarchicalReferences, direction=ua.BrowseDirection.Inverse)
                    
                    if not parent_refs:
                        break
                    
                    # Get first parent (assuming single parent hierarchy)
                    parent_node = self.client.get_node(parent_refs[0].NodeId)
                    parent_name = parent_node.read_display_name().Text
                    
                    parent_path.append(parent_name)
                    current_node = parent_node
                    
                    # Stop at root or after reasonable depth
                    if parent_node.nodeid.to_string() == "i=84" or len(parent_path) > 10:
                        break
            except Exception:
                pass
            
            # Reverse path for correct order
            parent_path.reverse()
            structure_info["parent_path"] = "/".join(parent_path)
            
        except Exception as e:
            logger.error(f"Error getting structure info for node {node_id}: {str(e)}")
        
        return structure_info

    async def subscribe_to_node(self, node_id: str, display_name: str):
        """
        Subscribe to data changes for a node
        
        Args:
            node_id: Node ID
            display_name: Display name
        """
        if not self.connected or not self.client:
            self.connection_status_changed.emit(
                ConnectionStatus.ERROR, 
                "Not connected to server"
            )
            return
        
        try:
            logger.info(f"Subscribing to node: {node_id} ({display_name})")
            
            # Create subscription if needed
            if not self.subscription:
                self.subscription = await self.client.create_subscription(500, self)
            
            node = self.client.get_node(node_id)
            
            # Try to read value to verify node is valid
            try:
                initial_value = await node.read_value()
            except Exception as e:
                error_msg = f"Error reading node {node_id}: {str(e)}"
                logger.error(error_msg)
                self.connection_status_changed.emit(ConnectionStatus.ERROR, error_msg)
                return
            
            # Subscribe to data changes
            handle = await self.subscription.subscribe_data_change(node)
            self.subscription_handles[node_id] = (handle, display_name)
            
            # Get structure info
            structure_info = self.get_node_structure_info(node_id)
            
            # Add to JSON output
            self.json_output_manager.add_subscription(
                node_id, 
                display_name, 
                initial_value,
                structure_info["parent_path"]
            )
            
            # Add to config
            self.config.subscribed_nodes[node_id] = display_name
            
            # Emit signal
            self.node_subscribed.emit(node_id, display_name, initial_value)
            
            logger.info(f"Subscribed to node: {node_id} ({display_name})")
            
        except Exception as e:
            error_msg = f"Error subscribing to node {node_id}: {str(e)}"
            logger.error(error_msg)
            self.connection_status_changed.emit(ConnectionStatus.ERROR, error_msg)
    
    
    async def unsubscribe_all(self):
        """Unsubscribe from all nodes"""
        if not self.connected or not self.client or not self.subscription:
            return
        
        try:
            logger.info("Unsubscribing from all nodes")
            
            # Get all node IDs
            node_ids = list(self.subscription_handles.keys())
            
            # Unsubscribe from each node
            for node_id in node_ids:
                await self.unsubscribe_from_node(node_id)
            
            # Clear subscription handles
            self.subscription_handles.clear()
            
            # Clear subscribed nodes in config
            self.config.subscribed_nodes.clear()
            
            logger.info("Unsubscribed from all nodes")
            
        except Exception as e:
            logger.error(f"Error unsubscribing from all nodes: {str(e)}")

    async def unsubscribe_from_node(self, node_id: str):
        """
        Unsubscribe from data changes for a node
        
        Args:
            node_id: Node ID
        """
        if not self.connected or not self.client or not self.subscription:
            return
        
        try:
            logger.info(f"Unsubscribing from node: {node_id}")
            
            if node_id in self.subscription_handles:
                handle, _ = self.subscription_handles[node_id]
                await self.subscription.unsubscribe(handle)
                del self.subscription_handles[node_id]
                
                # Remove from JSON output
                self.json_output_manager.remove_subscription(node_id)
                
                # Remove from config
                if node_id in self.config.subscribed_nodes:
                    del self.config.subscribed_nodes[node_id]
                
                # Emit signal
                self.node_unsubscribed.emit(node_id)
                
                logger.info(f"Unsubscribed from node: {node_id}")
            
        except Exception as e:
            logger.warning(f"Error unsubscribing from node {node_id}: {str(e)}")
    
    
    async def register_node(self, node_id: str, node_info: Dict[str, Any]):
        """
        Register a node for writing/monitoring
        
        Args:
            node_id: Node ID
            node_info: Node information dictionary
        """
        if not self.connected or not self.client:
            self.connection_status_changed.emit(
                ConnectionStatus.ERROR, 
                "Not connected to server"
            )
            return
        
        try:
            logger.info(f"Registering node: {node_id}")
            
            # Create subscription if needed
            if not self.subscription:
                self.subscription = await self.client.create_subscription(500, self)
            
            node = self.client.get_node(node_id)
            
            # Try to read value to verify node is valid
            try:
                initial_value = await node.read_value()
            except Exception as e:
                error_msg = f"Error reading node {node_id}: {str(e)}"
                logger.error(error_msg)
                self.connection_status_changed.emit(ConnectionStatus.ERROR, error_msg)
                return
            
            # Read node class to verify it's a variable
            node_class = await node.read_node_class()
            if node_class != ua.NodeClass.Variable:
                error_msg = f"Node {node_id} is not a variable node"
                logger.error(error_msg)
                self.connection_status_changed.emit(ConnectionStatus.ERROR, error_msg)
                return
            
            # Read access level to verify it's writable
            access_level = await node.read_attribute(ua.AttributeIds.AccessLevel)
            writable = bool(access_level.Value.Value & ua.AccessLevel.CurrentWrite)
            
            # Get data type
            data_type_node = await node.read_data_type()
            data_type_name = await self.client.get_node(data_type_node).read_browse_name()
            data_type = data_type_name.Name
            
            # Preserve node_type from node_info
            node_type = node_info.get("node_type", "Standard")
            toggle_interval = node_info.get("toggle_interval", 1.0)
            
            logger.debug(f"Registering node {node_id} with type {node_type} and interval {toggle_interval}")
            
            # Subscribe to data changes
            handle = await self.subscription.subscribe_data_change(node)
            self.subscription_handles[node_id] = (handle, node_info.get("display_name", "Unknown"))
            
            # Store additional information
            registered_node_info = {
                "display_name": node_info.get("display_name", "Unknown"),
                "data_type": data_type,
                "node_type": node_type,  # Ensure node_type is preserved
                "toggle_interval": toggle_interval,
                "last_value": initial_value,
                "writeable": writable
            }
            self.registered_nodes[node_id] = registered_node_info
            
            # Get structure info
            structure_info = self.get_node_structure_info(node_id)
            
            # Add to JSON output - this will create the file in the appropriate folder
            self.json_output_manager.add_registered_node(
                node_id,
                registered_node_info,
                structure_info
            )
            
            # Setup livebit functionality if needed
            if node_type == "LiveBit" and data_type == "Boolean":
                self.livebit_nodes[node_id] = toggle_interval
                self.last_toggle_time[node_id] = time.time()
                logger.info(f"Setting up LiveBit for node {node_id} with interval {toggle_interval}")
            
            # Add to config (if not already present)
            if node_id not in self.config.registered_nodes:
                self.config.registered_nodes[node_id] = {
                    "display_name": node_info.get("display_name", "Unknown"),
                    "data_type": data_type,
                    "node_type": node_type,  # Ensure node_type is saved
                    "toggle_interval": toggle_interval
                }
            else:
                # Update existing config with current settings
                self.config.registered_nodes[node_id]["data_type"] = data_type
                self.config.registered_nodes[node_id]["node_type"] = node_type
                self.config.registered_nodes[node_id]["toggle_interval"] = toggle_interval
            
            # Emit signal
            self.node_registered.emit(
                node_id,
                node_info.get("display_name", "Unknown"),
                data_type,
                initial_value
            )
            
            logger.info(f"Registered node: {node_id} ({node_info.get('display_name', 'Unknown')}) with type {node_type}")
            
        except Exception as e:
            error_msg = f"Error registering node {node_id}: {str(e)}"
            logger.error(error_msg)
            self.connection_status_changed.emit(ConnectionStatus.ERROR, error_msg)
    
    async def unregister_node(self, node_id: str):
        """
        Unregister a node
        
        Args:
            node_id: Node ID
        """
        if not self.connected or not self.client or not self.subscription:
            return
        
        try:
            logger.info(f"Unregistering node: {node_id}")
            
            if node_id in self.subscription_handles:
                handle, _ = self.subscription_handles[node_id]
                await self.subscription.unsubscribe(handle)
                del self.subscription_handles[node_id]
            
            # Remove from registered nodes
            if node_id in self.registered_nodes:
                del self.registered_nodes[node_id]
            
            # Remove from livebit nodes if present
            if node_id in self.livebit_nodes:
                del self.livebit_nodes[node_id]
            
            if node_id in self.last_toggle_time:
                del self.last_toggle_time[node_id]
            
            # Remove from JSON output - this will delete the file
            self.json_output_manager.remove_registered_node(node_id)
            
            # Remove from config
            if node_id in self.config.registered_nodes:
                del self.config.registered_nodes[node_id]
            
            logger.info(f"Unregistered node: {node_id}")
            
        except Exception as e:
            logger.warning(f"Error unregistering node {node_id}: {str(e)}")
    
    async def write_value(self, node_id: str, value: Any, save_value: bool = True):
        """
        Write a value to a node
        
        Args:
            node_id: Node ID
            value: Value to write
            save_value: Whether to save the value for reconnection
            
        Returns:
            (success, message) tuple
        """
        if not self.connected or not self.client:
            return False, "Not connected to server"
        
        try:
            logger.info(f"Writing value to node {node_id}: {value}")
            
            node = self.client.get_node(node_id)
            
            # Check if node is variable
            node_class = await node.read_node_class()
            if node_class != ua.NodeClass.Variable:
                return False, f"Node {node_id} is not a variable node"
            
            # Check if node is writable
            access_level = await node.read_attribute(ua.AttributeIds.AccessLevel)
            if not (access_level.Value.Value & ua.AccessLevel.CurrentWrite):
                return False, f"Node {node_id} is not writable"
            
            # Different approaches to writing - try multiple methods
            methods_tried = 0
            last_exception = None
            
            # Method 1: Try writing the direct attribute first (this worked in the logs)
            try:
                logger.debug(f"Attempting to write direct value: {value}")
                await node.write_attribute(ua.AttributeIds.Value, ua.DataValue(ua.Variant(value)))
                logger.info(f"Successfully wrote value to node {node_id}: {value}")
                
                # Update registered node value if needed
                if node_id in self.registered_nodes and save_value:
                    self.registered_nodes[node_id]["last_value"] = value
                    
                    # Update in config
                    if node_id in self.config.registered_nodes:
                        self.config.registered_nodes[node_id]["last_value"] = value
                
                # Emit signal
                self.node_write_completed.emit(node_id, True, "Write successful")
                
                return True, "Write successful"
            except Exception as e1:
                methods_tried += 1
                last_exception = e1
                logger.warning(f"Direct attribute write failed: {str(e1)}, trying Variant approach")
                
                # Method 2: Try the Variant approach
                try:
                    logger.debug(f"Attempting to write value using Variant approach: {value}")
                    variant = ua.Variant(value)
                    await node.write_value(variant)
                    logger.info(f"Successfully wrote value to node {node_id}: {value}")
                    
                    # Update registered node value if needed
                    if node_id in self.registered_nodes and save_value:
                        self.registered_nodes[node_id]["last_value"] = value
                        
                        # Update in config
                        if node_id in self.config.registered_nodes:
                            self.config.registered_nodes[node_id]["last_value"] = value
                    
                    # Emit signal
                    self.node_write_completed.emit(node_id, True, "Write successful")
                    
                    return True, "Write successful"
                except Exception as e2:
                    methods_tried += 1
                    last_exception = e2
                    logger.warning(f"Variant write failed: {str(e2)}, trying write_values")
                    
                    # Method 3: Try the client's write_values method
                    try:
                        logger.debug(f"Attempting to write using write_values: {value}")
                        await self.client.write_values([node], [value])
                        logger.info(f"Successfully wrote value to node {node_id}: {value}")
                        
                        # Update registered node value if needed
                        if node_id in self.registered_nodes and save_value:
                            self.registered_nodes[node_id]["last_value"] = value
                            
                            # Update in config
                            if node_id in self.config.registered_nodes:
                                self.config.registered_nodes[node_id]["last_value"] = value
                        
                        # Emit signal
                        self.node_write_completed.emit(node_id, True, "Write successful")
                        
                        return True, "Write successful"
                    except Exception as e3:
                        methods_tried += 1
                        last_exception = e3
                        error_msg = f"All write methods failed ({methods_tried}) for node {node_id}: {str(last_exception)}"
                        logger.error(error_msg)
                        
                        # Emit signal
                        self.node_write_completed.emit(node_id, False, error_msg)
                        
                        return False, error_msg
        
        except Exception as e:
            error_msg = f"Error writing to node {node_id}: {str(e)}"
            logger.error(error_msg)
            
            # Emit signal
            self.node_write_completed.emit(node_id, False, error_msg)
            
            return False, error_msg

    async def call_method(self, parent_id: str, method_id: str, *args):
        """
        Call a method on the server
        
        Args:
            parent_id: Parent node ID
            method_id: Method node ID
            *args: Method arguments
            
        Returns:
            (success, result) tuple
        """
        if not self.connected or not self.client:
            return False, "Not connected to server"
        
        try:
            logger.info(f"Calling method {method_id} on parent {parent_id} with args: {args}")
            
            parent_node = self.client.get_node(parent_id)
            method_node = self.client.get_node(method_id)
            
            # Call the method
            result = await parent_node.call_method(method_node, *args)
            
            # Emit signal
            self.method_called.emit(method_id, True, str(result))
            
            return True, result
            
        except Exception as e:
            error_msg = f"Error calling method {method_id}: {str(e)}"
            logger.error(error_msg)
            
            # Emit signal
            self.method_called.emit(method_id, False, error_msg)
            
            return False, error_msg
    
    def process_livebit_nodes(self):
        """Process livebit nodes (toggle boolean values)"""
        if not self.connected or not self.client:
            return
        
        current_time = time.time()
        
        for node_id, interval in list(self.livebit_nodes.items()):
            if node_id not in self.last_toggle_time:
                self.last_toggle_time[node_id] = current_time
                continue
                
            if current_time - self.last_toggle_time[node_id] >= interval:
                # Toggle the value
                if node_id in self.registered_nodes:
                    current_value = self.registered_nodes[node_id]["last_value"]
                    logger.debug(f"LiveBit toggling node {node_id} from {current_value} to {not current_value}")
                    
                    if isinstance(current_value, bool):
                        new_value = not current_value
                    else:
                        new_value = True  # Default to True if current value is not boolean
                    
                    # Schedule the write operation
                    if self.loop:
                        asyncio.run_coroutine_threadsafe(
                            self.write_value(node_id, new_value, False),  # Don't save livebit values to config
                            self.loop
                        )
                    
                    # Update last toggle time
                    self.last_toggle_time[node_id] = current_time
    
    # Add these methods to the client_core.py file right after the process_livebit_nodes method:

    # Remove this method as it's no longer needed:
    """
    def check_custom_node_writes(self):
        # This method is removed - file watcher handles this now
    """

    def datachange_notification(self, node: Node, val: Any, data: ua.DataValue):
        """Callback for data change notifications"""
        try:
            node_id = node.nodeid.to_string()
            
            # Handle different data structures in different asyncua versions
            if hasattr(data, 'SourceTimestamp') and data.SourceTimestamp:
                timestamp = data.SourceTimestamp
            elif hasattr(data, 'ServerTimestamp') and data.ServerTimestamp:
                timestamp = data.ServerTimestamp
            else:
                # Fallback to current time if no timestamps available
                timestamp = datetime.now()
                
            timestamp_str = timestamp.isoformat() if hasattr(timestamp, 'isoformat') else str(timestamp)
            
            # Handle subscription
            if node_id in self.subscription_handles:
                _, display_name = self.subscription_handles[node_id]
                
                # Update JSON output for subscriptions
                self.json_output_manager.update_subscription_value(node_id, val)
                
                # Emit signal
                self.subscription_data_changed.emit(node_id, val, timestamp_str)
            
            # Handle registered node
            if node_id in self.registered_nodes:
                self.registered_nodes[node_id]["last_value"] = val
                
                # Check if this is a custom node that we're controlling via file
                node_info = self.registered_nodes[node_id]
                if node_info.get("node_type") == "Custom":
                    # For custom nodes, we only update the file after successful writes
                    # Not on general data changes to prevent conflicts
                    if not self.json_output_manager.active_write_requests.get(node_id):
                        # Only update if we're not currently writing to this node
                        self.json_output_manager.update_registered_node_value(node_id, val)
                else:
                    # For non-custom nodes, update normally
                    self.json_output_manager.update_registered_node_value(node_id, val)
                
                # Emit signal
                self.subscription_data_changed.emit(node_id, val, timestamp_str)
            
        except Exception as e:
            logger.error(f"Error in data change notification: {str(e)}")

    # Add a check to on_file_changed to not process our own updates:
    
    def on_file_changed(self, filepath: str):
        """Handle file change"""
        try:
            with open(filepath, 'r') as f:
                node_data = json.load(f)
            
            node_id = node_data.get("node_id")
            if not node_id:
                return
            
            # Check if value has actually changed
            old_value = None
            if node_id in self.registered_nodes_data:
                old_value = self.registered_nodes_data[node_id].get("value")
            
            new_value = node_data.get("value")
            
            # Only request write if value changed and not if metadata changed
            if new_value != old_value:
                logger.info(f"External change detected for node {node_id}: {old_value} -> {new_value}")
                
                # Check if we're currently writing to this node
                if node_id not in self.active_write_requests:
                    self.request_write(node_id, new_value, filepath)
                else:
                    logger.debug(f"Skipping write request for {node_id} - write already in progress")
            
            # Update internal data
            self.registered_nodes_data[node_id] = node_data
            self.json_updated.emit(filepath)
            
        except Exception as e:
            logger.error(f"Error processing file change for {filepath}: {str(e)}")

    def on_json_updated(self, filename: str):
        """
        Handle JSON output file update
        
        Args:
            filename: Updated filename
        """
        # Emit signal to UI
        self.json_updated.emit(filename)
import logging
from typing import Dict, Any, Optional, List, Tuple, Union, Set
import asyncio

from asyncua import Client, Node, ua
from asyncua.ua.uatypes import ExtensionObject

from utils import get_logger

logger = get_logger("extension_objects")

class ExtensionObjectManager:
    """Manager for handling OPC UA extension objects and data type dictionaries"""
    
    def __init__(self):
        """Initialize extension object manager"""
        self.data_types = {}  # Dictionary of data types
        self.extension_object_types = set()  # Set of data types that are extension objects
        self.type_dictionaries = {}  # Dictionary of type dictionaries
    
    async def load_data_types(self, client: Client):
        """
        Load data types from the server
        
        Args:
            client: Connected OPC UA client
        """
        try:
            logger.info("Loading data types from server")
            
            # Get DataTypeSystem node
            types_node = client.get_node(ua.ObjectIds.OPCBinarySchema_TypeSystem)
            
            # Get type dictionaries
            try:
                type_dict_nodes = await types_node.get_children()
                
                for node in type_dict_nodes:
                    try:
                        # Get node browse name
                        name = await node.read_browse_name()
                        logger.debug(f"Processing type dictionary: {name.Name}")
                        
                        # Get dictionary data
                        dict_data = await node.read_value()
                        
                        # Store dictionary
                        if dict_data and hasattr(dict_data, 'ByteString'):
                            self.type_dictionaries[name.Name] = dict_data.ByteString
                            logger.debug(f"Loaded dictionary: {name.Name} ({len(dict_data.ByteString)} bytes)")
                    except Exception as e:
                        logger.warning(f"Error processing type dictionary: {str(e)}")
            except Exception as e:
                logger.warning(f"Error getting type dictionaries: {str(e)}")
            
            # Get custom data types
            try:
                # Browse for data type nodes using multiple approaches
                try:
                    # First, try to access the DataTypes node if it exists
                    try:
                        data_types_node = client.get_node(ua.ObjectIds.DataTypes)
                    except AttributeError:
                        # Fallback to BaseDataType
                        data_types_node = client.get_node(ua.ObjectIds.BaseDataType)
                    
                    data_type_nodes = await data_types_node.get_children()
                    
                    # Process data type nodes
                    for node in data_type_nodes:
                        await self._process_data_type_node(client, node)
                except Exception as e2:
                    logger.warning(f"Error accessing data types: {str(e2)}")
            except Exception as e:
                logger.warning(f"Error processing data types: {str(e)}")
            
            logger.info(f"Loaded {len(self.data_types)} data types, {len(self.extension_object_types)} extension object types")
        
        except Exception as e:
            logger.error(f"Error loading data types: {str(e)}")
    
    async def _process_data_type_node(self, client: Client, node: Node, parent_is_extension: bool = False):
        """
        Process a data type node recursively
        
        Args:
            client: OPC UA client
            node: Data type node
            parent_is_extension: Whether the parent is an extension object
        """
        try:
            # Get node ID and browse name
            node_id = node.nodeid.to_string()
            browse_name = await node.read_browse_name()
            
            # Store data type
            self.data_types[node_id] = {
                'name': browse_name.Name,
                'is_extension': False
            }
            
            # Check if this is a structure type
            if browse_name.Name == "Structure" or browse_name.Name == "ExtensionObject" or parent_is_extension:
                self.data_types[node_id]['is_extension'] = True
                self.extension_object_types.add(node_id)
            
            # Get child data types
            children = await node.get_children()
            for child in children:
                await self._process_data_type_node(client, child, self.data_types[node_id]['is_extension'])
        
        except Exception as e:
            logger.warning(f"Error processing data type node: {str(e)}")
    
    async def is_extension_object(self, client: Client, data_type_id: Union[str, ua.NodeId]) -> bool:
        """
        Check if a data type is an extension object
        
        Args:
            client: OPC UA client
            data_type_id: Data type node ID
            
        Returns:
            True if it's an extension object, False otherwise
        """
        # Convert to string if needed
        if isinstance(data_type_id, ua.NodeId):
            data_type_id = data_type_id.to_string()
        
        # Check if already known
        if data_type_id in self.extension_object_types:
            return True
        
        # Check if parent type is an extension object
        try:
            node = client.get_node(data_type_id)
            parent_refs = await node.get_references(refs=ua.ObjectIds.HasSubtype, direction=ua.BrowseDirection.Inverse)
            
            for ref in parent_refs:
                parent_id = ref.NodeId.to_string()
                
                # If parent is in extension object types, this is also an extension object
                if parent_id in self.extension_object_types:
                    self.extension_object_types.add(data_type_id)
                    if data_type_id in self.data_types:
                        self.data_types[data_type_id]['is_extension'] = True
                    return True
                
                # Check parent recursively
                if await self.is_extension_object(client, parent_id):
                    self.extension_object_types.add(data_type_id)
                    if data_type_id in self.data_types:
                        self.data_types[data_type_id]['is_extension'] = True
                    return True
        
        except Exception as e:
            logger.warning(f"Error checking if data type is extension object: {str(e)}")
        
        return False
    
    async def decode_extension_object(self, value: Any) -> Optional[Dict[str, Any]]:
        """
        Decode an extension object value
        
        Args:
            value: Extension object value
            
        Returns:
            Decoded value as a dictionary, or None if decoding failed
        """
        if not isinstance(value, ExtensionObject):
            return None
        
        try:
            # Get decoded body if already decoded
            if hasattr(value, "decoded_body") and value.decoded_body is not None:
                # Convert to dictionary if possible
                result = {}
                
                # Try to get all fields
                for field_name in dir(value.decoded_body):
                    # Skip private fields and methods
                    if field_name.startswith('_') or callable(getattr(value.decoded_body, field_name)):
                        continue
                    
                    # Get field value
                    field_value = getattr(value.decoded_body, field_name)
                    
                    # Store in result
                    result[field_name] = field_value
                
                return result
            
            # Return the raw body as fallback
            return {"raw_body": str(value.body)}
        
        except Exception as e:
            logger.warning(f"Error decoding extension object: {str(e)}")
            return None
    async def get_extension_object_type_info(self, client: Client, data_type_id: Union[str, ua.NodeId]) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about an extension object type
        
        Args:
            client: OPC UA client
            data_type_id: Data type node ID
            
        Returns:
            Dictionary with type information, or None if not available
        """
        try:
            # Convert to NodeId if needed
            if isinstance(data_type_id, str):
                data_type_id = ua.NodeId.from_string(data_type_id)
            
            # Get the data type node
            data_type_node = client.get_node(data_type_id)
            
            # Get the browse name
            browse_name = await data_type_node.read_browse_name()
            display_name = await data_type_node.read_display_name()
            
            # Try to get the description
            try:
                description = await data_type_node.read_attribute(ua.AttributeIds.Description)
                description_text = description.Value.Value.Text if description.Value.Value else ""
            except Exception:
                description_text = ""
            
            # Try to get the data type dictionary
            dictionary_info = None
            try:
                # Look for HasEncoding references
                encoding_refs = await data_type_node.get_references(
                    refs=ua.ObjectIds.HasEncoding
                )
                
                for ref in encoding_refs:
                    encoding_node = client.get_node(ref.NodeId)
                    encoding_name = await encoding_node.read_browse_name()
                    
                    # Look for HasDescription references from the encoding node
                    desc_refs = await encoding_node.get_references(
                        refs=ua.ObjectIds.HasDescription
                    )
                    
                    for desc_ref in desc_refs:
                        dict_node = client.get_node(desc_ref.NodeId)
                        dict_name = await dict_node.read_browse_name()
                        dictionary_info = {
                            "Name": dict_name.Name,
                            "NodeId": desc_ref.NodeId.to_string()
                        }
                        break
                    
                    if dictionary_info:
                        break
            except Exception as e:
                logger.warning(f"Error getting dictionary info: {str(e)}")
            
            # Return type information
            return {
                "BrowseName": browse_name.Name,
                "DisplayName": display_name.Text,
                "Description": description_text,
                "Dictionary": dictionary_info
            }
        
        except Exception as e:
            logger.warning(f"Error getting extension object type info: {str(e)}")
            return None
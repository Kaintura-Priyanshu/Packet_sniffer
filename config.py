#!/usr/bin/env python3
class SnifferConfig:
    """
    Configuration class for packet sniffer settings
    """
    
    # Network settings
    DEFAULT_INTERFACE = None  # Use default interface
    
    # Buffer sizes
    BUFFER_SIZE = 65535  # Maximum packet size
    SOCKET_TIMEOUT = 1.0  # Socket timeout in seconds
    
    # Display options
    MAX_PAYLOAD_DISPLAY = 50  # Maximum payload bytes to display
    
    # Protocol filters (comma separated or None for all)
    FILTER_PROTOCOLS = None  # e.g., ['TCP', 'UDP', 'ICMP']
    
    # Logging options
    LOG_LEVEL = 'INFO'  # DEBUG, INFO, WARNING, ERROR
    
    # File output
    FILE_EXTENSION = '.log'
    
    @classmethod
    def get_protocol_filter(cls):
        """
        Get protocol filter as a set for faster lookup
        
        Returns:
            set: Set of protocol names to filter, or None for all
        """
        if cls.FILTER_PROTOCOLS is None:
            return None
        return set(cls.FILTER_PROTOCOLS)
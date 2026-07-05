#!/usr/bin/env python3
import struct
import socket
from datetime import datetime
import binascii

class PacketAnalyzer:
    """
    Handles packet parsing and analysis
    """
    
    # Ethernet protocol types
    ETH_P_IP = 0x0800
    ETH_P_ARP = 0x0806
    ETH_P_IPV6 = 0x86DD
    
    # IP protocol numbers
    IP_PROTO_TCP = 6
    IP_PROTO_UDP = 17
    IP_PROTO_ICMP = 1
    IP_PROTO_IGMP = 2
    
    def __init__(self):
        """
        Initialize packet analyzer
        """
        self.protocol_names = {
            self.IP_PROTO_TCP: 'TCP',
            self.IP_PROTO_UDP: 'UDP',
            self.IP_PROTO_ICMP: 'ICMP',
            self.IP_PROTO_IGMP: 'IGMP'
        }
        
        self.icmp_type_names = {
            0: 'Echo Reply',
            3: 'Destination Unreachable',
            4: 'Source Quench',
            5: 'Redirect',
            8: 'Echo Request',
            11: 'Time Exceeded',
            12: 'Parameter Problem',
            13: 'Timestamp Request',
            14: 'Timestamp Reply'
        }
        
        self.tcp_flags = {
            'SYN': 0x02,
            'ACK': 0x10,
            'FIN': 0x01,
            'RST': 0x04,
            'PSH': 0x08,
            'URG': 0x20
        }
    
    def parse_packet(self, packet_data, timestamp=None):
        """
        Parse raw packet data
        
        Args:
            packet_data: Raw packet bytes
            timestamp: Packet timestamp
            
        Returns:
            dict: Parsed packet information
        """
        if timestamp is None:
            timestamp = datetime.now()
            
        result = {
            'timestamp': timestamp,
            'length': len(packet_data),
            'protocol': 'Unknown',
            'payload': b'',
            'raw': packet_data
        }
        
        try:
            # Parse Ethernet header (14 bytes)
            eth_header = packet_data[:14]
            eth_data = self.parse_ethernet(eth_header)
            result['ethernet'] = eth_data
            
            # Determine next protocol
            eth_type = eth_data['type']
            
            # Parse IP packet
            if eth_type == self.ETH_P_IP:
                ip_data = self.parse_ip(packet_data[14:])
                result['ip'] = ip_data
                result['protocol'] = ip_data['protocol_name']
                
                # Parse transport layer
                ip_header_len = ip_data['header_length']
                transport_data = packet_data[14 + ip_header_len:]
                
                if ip_data['protocol'] == self.IP_PROTO_TCP:
                    result['tcp'] = self.parse_tcp(transport_data)
                    
                elif ip_data['protocol'] == self.IP_PROTO_UDP:
                    result['udp'] = self.parse_udp(transport_data)
                    
                elif ip_data['protocol'] == self.IP_PROTO_ICMP:
                    result['icmp'] = self.parse_icmp(transport_data)
                
                # Extract payload
                if ip_data['protocol'] in [self.IP_PROTO_TCP, self.IP_PROTO_UDP]:
                    result['payload'] = self.extract_payload(transport_data, ip_data['protocol'])
                    
            elif eth_type == self.ETH_P_ARP:
                result['protocol'] = 'ARP'
                
            elif eth_type == self.ETH_P_IPV6:
                result['protocol'] = 'IPv6'
                
        except Exception as e:
            # If parsing fails, at least return what we have
            result['parse_error'] = str(e)
            
        return result
    
    def parse_ethernet(self, data):
        """
        Parse Ethernet header
        
        Args:
            data: Ethernet header bytes
            
        Returns:
            dict: Ethernet header information
        """
        # Unpack Ethernet header (6 bytes dest MAC, 6 bytes src MAC, 2 bytes type)
        dst_mac, src_mac, eth_type = struct.unpack('!6s6sH', data)
        
        return {
            'dst_mac': self.format_mac(dst_mac),
            'src_mac': self.format_mac(src_mac),
            'type': eth_type,
            'type_hex': f'0x{eth_type:04x}'
        }
    
    def parse_ip(self, data):
        """
        Parse IP header
        
        Args:
            data: IP header bytes
            
        Returns:
            dict: IP header information
        """
        # Parse first 20 bytes of IP header
        version_ihl = data[0]
        version = version_ihl >> 4
        header_length = (version_ihl & 0x0F) * 4
        
        tos = data[1]
        total_length = struct.unpack('!H', data[2:4])[0]
        identification = struct.unpack('!H', data[4:6])[0]
        flags_fragment = struct.unpack('!H', data[6:8])[0]
        ttl = data[8]
        protocol = data[9]
        checksum = struct.unpack('!H', data[10:12])[0]
        src_ip = socket.inet_ntoa(data[12:16])
        dst_ip = socket.inet_ntoa(data[16:20])
        
        # Get protocol name
        protocol_name = self.protocol_names.get(protocol, f'Protocol-{protocol}')
        
        return {
            'version': version,
            'header_length': header_length,
            'tos': tos,
            'total_length': total_length,
            'identification': identification,
            'ttl': ttl,
            'protocol': protocol,
            'protocol_name': protocol_name,
            'checksum': f'0x{checksum:04x}',
            'src': src_ip,
            'dst': dst_ip
        }
    
    def parse_tcp(self, data):
        """
        Parse TCP header
        
        Args:
            data: TCP header bytes
            
        Returns:
            dict: TCP header information
        """
        if len(data) < 20:
            return None
            
        src_port, dst_port, seq_num, ack_num, flags_offset = struct.unpack('!HHIIH', data[:14])
        offset = (flags_offset >> 12) & 0xF
        header_length = offset * 4
        flags = flags_offset & 0x3F
        
        # Parse TCP flags
        flag_names = []
        for name, value in self.tcp_flags.items():
            if flags & value:
                flag_names.append(name)
        
        return {
            'src_port': src_port,
            'dst_port': dst_port,
            'sequence_number': seq_num,
            'acknowledgment_number': ack_num,
            'header_length': header_length,
            'flags': ','.join(flag_names) if flag_names else 'None',
            'flags_hex': f'0x{flags:02x}',
            'window_size': struct.unpack('!H', data[14:16])[0],
            'checksum': f'0x{struct.unpack("!H", data[16:18])[0]:04x}',
            'urgent_pointer': struct.unpack('!H', data[18:20])[0]
        }
    
    def parse_udp(self, data):
        """
        Parse UDP header
        
        Args:
            data: UDP header bytes
            
        Returns:
            dict: UDP header information
        """
        if len(data) < 8:
            return None
            
        src_port, dst_port, length, checksum = struct.unpack('!HHHH', data[:8])
        
        return {
            'src_port': src_port,
            'dst_port': dst_port,
            'length': length,
            'checksum': f'0x{checksum:04x}'
        }
    
    def parse_icmp(self, data):
        """
        Parse ICMP header
        
        Args:
            data: ICMP header bytes
            
        Returns:
            dict: ICMP header information
        """
        if len(data) < 8:
            return None
            
        icmp_type = data[0]
        code = data[1]
        checksum = struct.unpack('!H', data[2:4])[0]
        
        # Get ICMP type name
        type_name = self.icmp_type_names.get(icmp_type, f'Type-{icmp_type}')
        
        return {
            'type': icmp_type,
            'type_name': type_name,
            'code': code,
            'checksum': f'0x{checksum:04x}'
        }
    
    def extract_payload(self, data, protocol):
        """
        Extract payload from transport layer
        
        Args:
            data: Transport layer data
            protocol: Protocol number
            
        Returns:
            bytes: Payload data
        """
        try:
            if protocol == self.IP_PROTO_TCP and len(data) > 20:
                offset = (data[12] >> 4) & 0xF
                header_length = offset * 4
                return data[header_length:]
                
            elif protocol == self.IP_PROTO_UDP and len(data) > 8:
                return data[8:]
                
        except Exception:
            pass
            
        return b''
    
    @staticmethod
    def format_mac(mac_bytes):
        """
        Format MAC address from bytes to string
        
        Args:
            mac_bytes: MAC address bytes
            
        Returns:
            str: Formatted MAC address
        """
        return ':'.join(f'{b:02x}' for b in mac_bytes)

    @staticmethod
    def format_hex(data, limit=None):
        """
        Format binary data as hex string
        
        Args:
            data: Binary data
            limit: Maximum bytes to display
            
        Returns:
            str: Hex representation
        """
        if limit and len(data) > limit:
            data = data[:limit]
        return ' '.join(f'{b:02x}' for b in data)
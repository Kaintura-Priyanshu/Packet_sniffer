#!/usr/bin/env python3
import socket
import struct
import time
import threading
from datetime import datetime
from collections import defaultdict
import argparse
import sys

# Import our custom modules
from analyzer import PacketAnalyzer
from config import SnifferConfig

class PacketSniffer:
    """
    Main packet sniffer class that captures and processes network packets
    """
    
    def __init__(self, interface=None, output_file=None, verbose=False):
        """
        Initialize the packet sniffer with configuration
        
        Args:
            interface: Network interface to sniff on (None for default)
            output_file: File to save captured packets
            verbose: Enable verbose output
        """
        self.interface = interface
        self.output_file = output_file
        self.verbose = verbose
        self.running = False
        self.packet_count = 0
        self.start_time = None
        self.stats = defaultdict(int)
        self.analyzer = PacketAnalyzer()
        
        # Create raw socket for packet capture
        self.socket = None
        
        # Output file handling
        self.output_handle = None
        
    def create_socket(self):
        """
        Create a raw socket for packet capture
        Requires root privileges in Linux
        """
        try:
            # AF_PACKET: Low-level packet interface (Linux specific)
            # SOCK_RAW: Provides raw packets without protocol processing
            # htons(ETH_P_ALL): Capture all Ethernet frames
            self.socket = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.htons(0x0003)  # ETH_P_ALL
            )
            
            # Set socket options for promiscuous mode (if interface specified)
            if self.interface:
                # Bind to specific interface
                self.socket.bind((self.interface, 0))
            
            # Set timeout to allow checking running status
            self.socket.settimeout(1.0)
            
            return True
            
        except PermissionError:
            print("[!] ERROR: Root privileges required for packet sniffing")
            print("[!] Please run with: sudo python3 sniffer.py")
            return False
            
        except Exception as e:
            print(f"[!] ERROR creating socket: {e}")
            return False
    
    def start_capture(self, packet_count=None):
        """
        Start capturing packets
        
        Args:
            packet_count: Number of packets to capture (None for infinite)
        """
        if not self.create_socket():
            return False
        
        self.running = True
        self.start_time = datetime.now()
        self.packet_count = 0
        
        # Open output file if specified
        if self.output_file:
            try:
                self.output_handle = open(self.output_file, 'w')
                self.output_handle.write("# Packet Sniffer Log\n")
                self.output_handle.write(f"# Started: {self.start_time}\n")
                self.output_handle.write("# " + "="*60 + "\n\n")
            except Exception as e:
                print(f"[!] ERROR opening output file: {e}")
                self.output_file = None
        
        print(f"[*] Starting packet capture on interface: {self.interface or 'default'}")
        print(f"[*] Press Ctrl+C to stop capture\n")
        print("=" * 80)
        
        try:
            captured = 0
            while self.running and (packet_count is None or captured < packet_count):
                try:
                    # Receive packet
                    packet_data, addr = self.socket.recvfrom(65535)
                    
                    # Process the packet
                    self.process_packet(packet_data, addr)
                    captured += 1
                    self.packet_count += 1
                    
                    # Print progress every 100 packets
                    if captured % 100 == 0:
                        print(f"[*] Captured {captured} packets...")
                        
                except socket.timeout:
                    # Check running status
                    if not self.running:
                        break
                    continue
                    
                except KeyboardInterrupt:
                    print("\n[*] Capture interrupted by user")
                    break
                    
                except Exception as e:
                    if self.verbose:
                        print(f"[!] Error receiving packet: {e}")
                    continue
                    
        finally:
            self.stop_capture()
            
        return True
    
    def process_packet(self, packet_data, address):
        """
        Process a captured packet
        
        Args:
            packet_data: Raw packet bytes
            address: Source address information
        """
        timestamp = datetime.now()
        
        try:
            # Parse the packet
            parsed_packet = self.analyzer.parse_packet(packet_data, timestamp)
            
            # Update statistics
            self.update_stats(parsed_packet)
            
            # Display packet information
            if self.verbose:
                self.display_packet(parsed_packet)
            
            # Save to file if configured
            if self.output_handle:
                self.save_packet(parsed_packet)
                
        except Exception as e:
            if self.verbose:
                print(f"[!] Error processing packet: {e}")
    
    def update_stats(self, packet):
        """
        Update packet statistics
        
        Args:
            packet: Parsed packet dictionary
        """
        protocol = packet.get('protocol', 'Unknown')
        self.stats[protocol] += 1
        
        # IP statistics
        if 'ip' in packet:
            self.stats['total_ip_packets'] += 1
            
            # Traffic by source IP
            src_ip = packet['ip'].get('src')
            if src_ip:
                self.stats[f'src_{src_ip}'] += 1
                
            # Traffic by destination IP  
            dst_ip = packet['ip'].get('dst')
            if dst_ip:
                self.stats[f'dst_{dst_ip}'] += 1
    
    def display_packet(self, packet):
        """
        Display packet information in human-readable format
        
        Args:
            packet: Parsed packet dictionary
        """
        timestamp = packet['timestamp'].strftime("%H:%M:%S.%f")[:-3]
        protocol = packet['protocol']
        length = packet['length']
        
        print(f"\n[{timestamp}] Protocol: {protocol} | Length: {length} bytes")
        
        if 'ethernet' in packet:
            eth = packet['ethernet']
            print(f"  ├─ Ethernet: {eth['src_mac']} -> {eth['dst_mac']}")
            
        if 'ip' in packet:
            ip = packet['ip']
            print(f"  ├─ IP: {ip['src']} -> {ip['dst']} (TTL: {ip['ttl']})")
            
        if 'tcp' in packet:
            tcp = packet['tcp']
            print(f"  ├─ TCP: Port {tcp['src_port']} -> {tcp['dst_port']}")
            if 'flags' in tcp:
                print(f"  │  └─ Flags: {tcp['flags']}")
                
        if 'udp' in packet:
            udp = packet['udp']
            print(f"  ├─ UDP: Port {udp['src_port']} -> {udp['dst_port']}")
            
        if 'icmp' in packet:
            icmp = packet['icmp']
            print(f"  ├─ ICMP: Type {icmp['type']} - {icmp['type_name']}")
        
        if packet.get('payload'):
            payload = packet['payload'][:50]  # Show first 50 bytes
            print(f"  └─ Payload: {payload}...")
    
    def save_packet(self, packet):
        """
        Save packet to output file
        
        Args:
            packet: Parsed packet dictionary
        """
        try:
            self.output_handle.write(f"Packet #{self.packet_count}\n")
            self.output_handle.write(f"Timestamp: {packet['timestamp']}\n")
            self.output_handle.write(f"Protocol: {packet['protocol']}\n")
            self.output_handle.write(f"Length: {packet['length']} bytes\n")
            
            if 'ethernet' in packet:
                eth = packet['ethernet']
                self.output_handle.write(f"Source MAC: {eth['src_mac']}\n")
                self.output_handle.write(f"Dest MAC: {eth['dst_mac']}\n")
                
            if 'ip' in packet:
                ip = packet['ip']
                self.output_handle.write(f"Source IP: {ip['src']}\n")
                self.output_handle.write(f"Dest IP: {ip['dst']}\n")
                
            self.output_handle.write("-" * 60 + "\n\n")
            self.output_handle.flush()
            
        except Exception as e:
            if self.verbose:
                print(f"[!] Error saving packet: {e}")
    
    def stop_capture(self):
        """
        Stop packet capture and cleanup
        """
        self.running = False
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            
        if self.output_handle:
            try:
                # Write summary
                duration = (datetime.now() - self.start_time).total_seconds()
                self.output_handle.write("\n" + "="*60 + "\n")
                self.output_handle.write("CAPTURE SUMMARY\n")
                self.output_handle.write(f"Total Packets: {self.packet_count}\n")
                self.output_handle.write(f"Duration: {duration:.2f} seconds\n")
                self.output_handle.write(f"Average: {self.packet_count/duration:.2f} packets/sec\n")
                self.output_handle.close()
            except:
                pass
        
        self.print_summary()
    
    def print_summary(self):
        """
        Print capture statistics
        """
        if self.packet_count == 0:
            print("\n[*] No packets captured")
            return
            
        duration = (datetime.now() - self.start_time).total_seconds()
        
        print("\n" + "=" * 80)
        print("CAPTURE SUMMARY")
        print("=" * 80)
        print(f"Total Packets: {self.packet_count}")
        print(f"Duration: {duration:.2f} seconds")
        print(f"Average: {self.packet_count/duration:.2f} packets/sec")
        
        print("\nProtocol Distribution:")
        for protocol, count in sorted(self.stats.items(), key=lambda x: x[1], reverse=True):
            if not protocol.startswith(('src_', 'dst_')):
                percentage = (count / self.packet_count) * 100
                print(f"  {protocol}: {count} packets ({percentage:.1f}%)")
        
        # Show top IP addresses
        print("\nTop Source IP Addresses:")
        src_ips = [(k[4:], v) for k, v in self.stats.items() if k.startswith('src_')]
        for ip, count in sorted(src_ips, key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip}: {count} packets")
            
        print("\nTop Destination IP Addresses:")
        dst_ips = [(k[4:], v) for k, v in self.stats.items() if k.startswith('dst_')]
        for ip, count in sorted(dst_ips, key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip}: {count} packets")
        
        print("=" * 80)

def main():
    """
    Main function - argument parsing and program entry point
    """
    parser = argparse.ArgumentParser(
        description="Professional Packet Sniffer for Kali Linux",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 sniffer.py                    # Capture on default interface
  sudo python3 sniffer.py -i eth0            # Capture on eth0
  sudo python3 sniffer.py -v                 # Verbose output
  sudo python3 sniffer.py -c 100             # Capture 100 packets
  sudo python3 sniffer.py -o capture.log     # Save to file
        """
    )
    
    parser.add_argument(
        '-i', '--interface',
        help='Network interface to sniff on',
        default=None
    )
    
    parser.add_argument(
        '-c', '--count',
        type=int,
        help='Number of packets to capture',
        default=None
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file for captured packets',
        default=None
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output (show packet details)'
    )
    
    args = parser.parse_args()
    
    # Check for root privileges
    if sys.platform == 'linux' and os.geteuid() != 0:
        print("[!] WARNING: Running without root privileges")
        print("[!] Packet capture may not work correctly")
        print("[!] Please run with: sudo python3 sniffer.py\n")
    
    # Create and start sniffer
    sniffer = PacketSniffer(
        interface=args.interface,
        output_file=args.output,
        verbose=args.verbose
    )
    
    try:
        sniffer.start_capture(args.count)
    except KeyboardInterrupt:
        print("\n[*] Capture terminated")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    import os
    sys.exit(main())
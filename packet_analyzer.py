#!/usr/bin/env python3


import socket
import struct
import textwrap
import sys
import argparse
from datetime import datetime
import json
import threading
import time

class PacketAnalyzer:
    def __init__(self, interface=None, output_file=None, filter_protocol=None):
        self.interface = interface
        self.output_file = output_file
        self.filter_protocol = filter_protocol
        self.packet_count = 0
        self.running = False
        
        # Protocol numbers
        self.protocols = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }
        
        # Common ports
        self.common_ports = {
            20: 'FTP-DATA',
            21: 'FTP',
            22: 'SSH',
            23: 'TELNET',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S'
        }

    def display_banner(self):
        """Display educational banner and warnings"""
        banner = """
        ╔═══════════════════════════════════════════════════════════════╗
        ║                    NETWORK PACKET ANALYZER                    ║
        ║                      Educational Tool                         ║
        ╠═══════════════════════════════════════════════════════════════╣
        ║  WARNING: Use only on networks you own or have permission    ║
        ║  to monitor. Unauthorized packet sniffing may be illegal.    ║
        ║                                                               ║
        ║  This tool is for educational and troubleshooting purposes    ║
        ║  only. Please use responsibly and ethically.                 ║
        ╚═══════════════════════════════════════════════════════════════╝
        """
        print(banner)
        
        # Confirmation prompt
        response = input("\nDo you have permission to monitor this network? (yes/no): ").lower()
        if response != 'yes':
            print("Exiting. Please only use this tool on networks you own or have permission to monitor.")
            sys.exit(1)

    def format_mac_addr(self, bytes_addr):
        """Format MAC address"""
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()

    def format_ip_addr(self, addr):
        """Format IP address"""
        return '.'.join(map(str, addr))

    def parse_ethernet_header(self, data):
        """Parse Ethernet header"""
        dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', data[:14])
        return {
            'dest_mac': self.format_mac_addr(dest_mac),
            'src_mac': self.format_mac_addr(src_mac),
            'eth_proto': socket.htons(eth_proto)
        }

    def parse_ipv4_header(self, data):
        """Parse IPv4 header"""
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        
        return {
            'version': version,
            'header_length': header_length,
            'ttl': ttl,
            'protocol': proto,
            'src_ip': self.format_ip_addr(src),
            'dest_ip': self.format_ip_addr(target)
        }

    def parse_icmp_header(self, data):
        """Parse ICMP header"""
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        return {
            'type': icmp_type,
            'code': code,
            'checksum': checksum
        }

    def parse_tcp_header(self, data):
        """Parse TCP header"""
        src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
        
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1
        
        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'sequence': sequence,
            'acknowledgment': acknowledgment,
            'offset': offset,
            'flags': {
                'URG': flag_urg,
                'ACK': flag_ack,
                'PSH': flag_psh,
                'RST': flag_rst,
                'SYN': flag_syn,
                'FIN': flag_fin
            }
        }

    def parse_udp_header(self, data):
        """Parse UDP header"""
        src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'length': length
        }

    def get_service_name(self, port):
        """Get service name for common ports"""
        return self.common_ports.get(port, f'Port {port}')

    def format_data(self, data, size=16):
        """Format data in hex and ASCII"""
        if len(data) == 0:
            return "No data"
        
        chars = []
        for i in range(0, min(len(data), 64), size):  # Limit to first 64 bytes
            byte_line = ' '.join([f'{byte:02x}' for byte in data[i:i+size]])
            ascii_line = ''.join([chr(byte) if 32 <= byte <= 126 else '.' for byte in data[i:i+size]])
            chars.append(f'{i:04x}: {byte_line:<48} {ascii_line}')
        
        return '\n'.join(chars)

    def analyze_packet(self, data):
        """Analyze a single packet"""
        packet_info = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'packet_number': self.packet_count,
            'size': len(data)
        }

        try:
            # Parse Ethernet header
            eth_header = self.parse_ethernet_header(data)
            packet_info['ethernet'] = eth_header
            
            # Check if it's IPv4
            if eth_header['eth_proto'] == 8:  # IPv4
                # Parse IPv4 header
                ipv4_header = self.parse_ipv4_header(data[14:])
                packet_info['ipv4'] = ipv4_header
                
                # Apply protocol filter if specified
                protocol_name = self.protocols.get(ipv4_header['protocol'], 'OTHER')
                if self.filter_protocol and protocol_name.lower() != self.filter_protocol.lower():
                    return None
                
                packet_info['protocol'] = protocol_name
                
                # Parse transport layer based on protocol
                if ipv4_header['protocol'] == 1:  # ICMP
                    icmp_header = self.parse_icmp_header(data[14 + ipv4_header['header_length']:])
                    packet_info['icmp'] = icmp_header
                    
                elif ipv4_header['protocol'] == 6:  # TCP
                    tcp_header = self.parse_tcp_header(data[14 + ipv4_header['header_length']:])
                    packet_info['tcp'] = tcp_header
                    packet_info['src_service'] = self.get_service_name(tcp_header['src_port'])
                    packet_info['dest_service'] = self.get_service_name(tcp_header['dest_port'])
                    
                    # Extract payload
                    payload_start = 14 + ipv4_header['header_length'] + tcp_header['offset']
                    payload = data[payload_start:]
                    if payload:
                        packet_info['payload'] = self.format_data(payload)
                    
                elif ipv4_header['protocol'] == 17:  # UDP
                    udp_header = self.parse_udp_header(data[14 + ipv4_header['header_length']:])
                    packet_info['udp'] = udp_header
                    packet_info['src_service'] = self.get_service_name(udp_header['src_port'])
                    packet_info['dest_service'] = self.get_service_name(udp_header['dest_port'])
                    
                    # Extract payload
                    payload_start = 14 + ipv4_header['header_length'] + 8
                    payload = data[payload_start:]
                    if payload:
                        packet_info['payload'] = self.format_data(payload)

        except Exception as e:
            packet_info['error'] = f"Parsing error: {str(e)}"

        return packet_info

    def display_packet(self, packet_info):
        """Display packet information in a readable format"""
        print(f"\n{'='*80}")
        print(f"Packet #{packet_info['packet_number']} - {packet_info['timestamp']}")
        print(f"Size: {packet_info['size']} bytes")
        print(f"{'='*80}")
        
        if 'error' in packet_info:
            print(f"ERROR: {packet_info['error']}")
            return
        
        # Ethernet layer
        if 'ethernet' in packet_info:
            eth = packet_info['ethernet']
            print(f"ETHERNET: {eth['src_mac']} → {eth['dest_mac']} (Type: 0x{eth['eth_proto']:04x})")
        
        # IPv4 layer
        if 'ipv4' in packet_info:
            ipv4 = packet_info['ipv4']
            protocol = packet_info.get('protocol', 'UNKNOWN')
            print(f"IPv4: {ipv4['src_ip']} → {ipv4['dest_ip']} (Protocol: {protocol}, TTL: {ipv4['ttl']})")
        
        # Transport layer
        if 'tcp' in packet_info:
            tcp = packet_info['tcp']
            flags = [flag for flag, value in tcp['flags'].items() if value]
            flags_str = '+'.join(flags) if flags else 'None'
            print(f"TCP: {packet_info['src_service']}({tcp['src_port']}) → {packet_info['dest_service']}({tcp['dest_port']}) [Flags: {flags_str}]")
            print(f"     Seq: {tcp['sequence']}, Ack: {tcp['acknowledgment']}")
            
        elif 'udp' in packet_info:
            udp = packet_info['udp']
            print(f"UDP: {packet_info['src_service']}({udp['src_port']}) → {packet_info['dest_service']}({udp['dest_port']}) (Length: {udp['length']})")
            
        elif 'icmp' in packet_info:
            icmp = packet_info['icmp']
            print(f"ICMP: Type {icmp['type']}, Code {icmp['code']}")
        
        # Payload
        if 'payload' in packet_info:
            print(f"\nPayload Data:")
            print(packet_info['payload'])

    def save_packet(self, packet_info):
        """Save packet information to file"""
        if self.output_file:
            try:
                with open(self.output_file, 'a') as f:
                    f.write(json.dumps(packet_info, indent=2) + '\n')
            except Exception as e:
                print(f"Error saving packet: {e}")

    def start_capture(self):
        """Start packet capture"""
        try:
            # Create raw socket
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            
            if self.interface:
                sock.bind((self.interface, 0))
            
            print(f"\nStarting packet capture...")
            print(f"Interface: {self.interface or 'All interfaces'}")
            print(f"Filter: {self.filter_protocol or 'All protocols'}")
            print(f"Output file: {self.output_file or 'None (console only)'}")
            print(f"Press Ctrl+C to stop\n")
            
            self.running = True
            
            while self.running:
                raw_data, addr = sock.recvfrom(65536)
                self.packet_count += 1
                
                packet_info = self.analyze_packet(raw_data)
                if packet_info:  # Only display if not filtered out
                    self.display_packet(packet_info)
                    self.save_packet(packet_info)
                
        except PermissionError:
            print("\nError: Permission denied. Try running with sudo privileges.")
        except KeyboardInterrupt:
            print(f"\n\nCapture stopped. Total packets captured: {self.packet_count}")
        except Exception as e:
            print(f"\nError during capture: {e}")
        finally:
            self.running = False

def main():
    parser = argparse.ArgumentParser(
        description='Network Packet Analyzer - Educational Tool',
        epilog='Example: sudo python3 packet_analyzer.py -i eth0 -f tcp -o packets.json'
    )
    
    parser.add_argument('-i', '--interface', 
                       help='Network interface to capture from (e.g., eth0, wlan0)')
    parser.add_argument('-f', '--filter', 
                       choices=['tcp', 'udp', 'icmp'],
                       help='Filter by protocol (tcp, udp, icmp)')
    parser.add_argument('-o', '--output',
                       help='Output file to save packet data (JSON format)')
    
    args = parser.parse_args()
    
    # Create analyzer instance
    analyzer = PacketAnalyzer(
        interface=args.interface,
        output_file=args.output,
        filter_protocol=args.filter
    )
    
    # Display banner and get confirmation
    analyzer.display_banner()
    
    # Check if running as root (required for raw sockets)
    if sys.platform.startswith('linux') and socket.geteuid() != 0:
        print("\nWarning: This tool requires root privileges on Linux.")
        print("Please run with sudo: sudo python3 packet_analyzer.py")
        sys.exit(1)
    
    # Start capture
    analyzer.start_capture()

if __name__ == "__main__":
    main()
# Network Packet Analyzer

A Python-based network packet sniffer and analyzer designed for educational purposes and network troubleshooting.

## ⚠️ IMPORTANT LEGAL NOTICE

**This tool is for educational and authorized network analysis only.**

- Only use on networks you own or have explicit written permission to monitor
- Unauthorized packet sniffing may violate local, state, and federal laws
- Users are solely responsible for compliance with applicable laws and regulations
- This tool includes built-in ethical safeguards and usage confirmations

## Features

- Real-time packet capture and analysis
- Support for Ethernet, IPv4, TCP, UDP, and ICMP protocols
- Detailed packet information display including:
  - Source and destination MAC addresses
  - Source and destination IP addresses
  - Protocol information and flags
  - Port numbers and common service identification
  - Payload data in hex and ASCII format
- Protocol filtering (TCP, UDP, ICMP)
- JSON output for further analysis
- Network interface selection
- Educational warnings and permission checks

## Requirements

- Python 3.6 or higher
- Linux/Unix-based operating system (required for raw sockets)
- Root/Administrator privileges
- Network interface access

## Installation

1. Clone or download the packet analyzer script
2. Ensure Python 3.6+ is installed:
   ```bash
   python3 --version
   ```

3. No additional packages required (uses only Python standard library)

## Usage

### Basic Usage

Run with root privileges (required for raw socket access):

```bash
sudo python3 packet_analyzer.py
```

### Command Line Options

```bash
sudo python3 packet_analyzer.py [OPTIONS]
```

**Options:**
- `-i, --interface`: Specify network interface (e.g., eth0, wlan0)
- `-f, --filter`: Filter by protocol (tcp, udp, icmp)
- `-o, --output`: Save packets to JSON file

### Examples

1. **Capture all packets on all interfaces:**
   ```bash
   sudo python3 packet_analyzer.py
   ```

2. **Capture only TCP packets on specific interface:**
   ```bash
   sudo python3 packet_analyzer.py -i eth0 -f tcp
   ```

3. **Capture UDP packets and save to file:**
   ```bash
   sudo python3 packet_analyzer.py -f udp -o network_analysis.json
   ```

4. **Monitor specific interface with output logging:**
   ```bash
   sudo python3 packet_analyzer.py -i wlan0 -o packets.json
   ```

### Finding Your Network Interface

To list available network interfaces:

```bash
# On Linux
ip link show

# Or using ifconfig
ifconfig -a

# Common interface names:
# eth0, eth1 - Ethernet interfaces
# wlan0, wlan1 - Wireless interfaces
# lo - Loopback interface
```

## Understanding the Output

### Packet Information Display

```
================================================================================
Packet #1 - 2024-01-15 10:30:45.123
Size: 74 bytes
================================================================================
ETHERNET: AA:BB:CC:DD:EE:FF → 11:22:33:44:55:66 (Type: 0x0800)
IPv4: 192.168.1.100 → 192.168.1.1 (Protocol: TCP, TTL: 64)
TCP: HTTP(80) → Port 54321 [Flags: SYN+ACK]
     Seq: 1234567890, Ack: 987654321

Payload Data:
0000: 48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d  HTTP/1.1 200 OK.
0010: 0a 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 74  .Content-Type: t
```

### Field Explanations

- **Packet #**: Sequential packet number
- **Timestamp**: Capture time with millisecond precision
- **Size**: Total packet size in bytes
- **ETHERNET**: MAC addresses and EtherType
- **IPv4**: IP addresses, protocol, and TTL
- **TCP/UDP/ICMP**: Transport layer details
- **Payload**: Packet data in hex and ASCII

## Output File Format

When using the `-o` option, packets are saved in JSON format:

```json
{
  "timestamp": "2024-01-15 10:30:45.123",
  "packet_number": 1,
  "size": 74,
  "ethernet": {
    "src_mac": "AA:BB:CC:DD:EE:FF",
    "dest_mac": "11:22:33:44:55:66",
    "eth_proto": 2048
  },
  "ipv4": {
    "src_ip": "192.168.1.100",
    "dest_ip": "192.168.1.1",
    "protocol": 6,
    "ttl": 64
  },
  "tcp": {
    "src_port": 80,
    "dest_port": 54321,
    "flags": {
      "SYN": 1,
      "ACK": 1
    }
  }
}
```

## Troubleshooting

### Permission Errors

```
Error: Permission denied. Try running with sudo privileges.
```

**Solution:** Run with sudo:
```bash
sudo python3 packet_analyzer.py
```

### No Packets Captured

1. **Check interface name:**
   ```bash
   ip link show
   ```

2. **Verify network activity:**
   - Generate traffic by browsing websites
   - Use ping command: `ping google.com`

3. **Try different interface:**
   ```bash
   sudo python3 packet_analyzer.py -i lo  # loopback interface
   ```

### Socket Errors

If you encounter socket-related errors:

1. Ensure you're running on Linux/Unix
2. Check that the interface exists and is up
3. Verify no other packet capture tools are running

## Educational Use Cases

This tool is excellent for learning:

- **Network Protocol Analysis**: Understanding TCP/IP stack
- **Network Troubleshooting**: Identifying connectivity issues
- **Security Education**: Learning about network monitoring
- **Protocol Implementation**: Seeing real protocol headers
- **Network Forensics**: Analyzing network behavior

## Limitations

- **Linux/Unix Only**: Raw sockets require Unix-like systems
- **Root Privileges**: Required for packet capture
- **IPv4 Only**: Currently supports IPv4 (not IPv6)
- **Basic Parsing**: Limited application layer protocol parsing
- **Performance**: Not optimized for high-traffic environments

## Security Considerations

- Tool includes ethical usage confirmations
- Captures only packet headers and basic payload
- No password or sensitive data extraction
- Includes usage warnings and legal notices
- Designed for educational transparency

## Contributing

For educational enhancements:
1. Add IPv6 support
2. Implement more application layer protocols
3. Add packet filtering capabilities
4. Improve payload analysis
5. Add statistical analysis features

## License

MIT License - See tool header for details.

## Disclaimer

This software is provided for educational purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations. The authors assume no liability for misuse of this tool.

---

**Remember: Always obtain proper authorization before monitoring network traffic.**
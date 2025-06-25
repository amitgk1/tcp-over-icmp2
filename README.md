# TCP-over-ICMP Tunnel

A transparent TCP-over-ICMP tunnel implementation in Python. This project allows you to tunnel TCP traffic through ICMP packets, useful for bypassing firewalls that block TCP but allow ICMP traffic.

## Features

- **Transparent tunneling**: All TCP traffic is automatically redirected through the tunnel
- **Automatic setup/cleanup**: iptables rules are automatically configured and cleaned up
- **Fragmentation support**: Large packets are automatically fragmented and reassembled
- **Connection management**: Robust connection tracking and cleanup
- **Reliability**: Packet retransmission and error handling
- **Production-ready**: Comprehensive error handling and edge case coverage

## Architecture

```
[Applications] → [iptables DNAT] → [Local Proxy] → [ICMP Tunnel] → [Server] → [Internet]
```

1. **iptables rules** redirect all outgoing TCP traffic to a local proxy
2. **Local proxy** encapsulates TCP data in ICMP packets
3. **ICMP tunnel** carries the data to the external server
4. **Server** decapsulates and forwards to real destinations

## Requirements

- Linux system with root access
- Python 3.12+
- iptables support
- Raw socket capabilities

## Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd tcp-over-icmp
   ```

2. **Install system dependencies:**
   ```bash
   sudo apt-get update
   sudo apt-get install python3-pip python3-dev iptables-persistent libnetfilter-queue-dev
   ```

3. **Install Python dependencies:**
   ```bash
   uv sync
   ```

## Usage

### Starting the Server

The server must be running on a machine outside the firewall:

```bash
# Run as root (required for raw socket access)
sudo uv run server

# Or with custom options
sudo uv run server --ip 192.168.1.100 --icmp-id 54321
```

### Starting the Client

On the machine behind the firewall:

```bash
# Run as root (required for iptables)
sudo uv run client 192.168.1.100

# Or with custom proxy port
sudo uv run client 192.168.1.100 --port 9090
```

### Example Workflow

1. **Start the server** on an external machine:
   ```bash
   sudo uv run server
   ```

2. **Start the client** on the machine behind the firewall:
   ```bash
   sudo uv run client <server-ip>
   ```

3. **Use applications normally** - all TCP traffic will be tunneled:
   ```bash
   # These will work through the tunnel
   curl https://example.com
   ssh user@remote-server
   wget http://download.example.com/file.zip
   ```

4. **Stop the tunnel** with Ctrl+C - iptables rules are automatically cleaned up

## Technical Details

### Packet Structure

The tunnel protocol uses a custom header structure:

```
[Packet Type][Sequence][Conn ID Len][Conn ID][Checksum][Fragment Info][Data]
    1 byte     4 bytes     1 byte    16 bytes   2 bytes    8 bytes    variable
```

### Packet Types

- `CONNECT` (1): Establish connection to destination
- `CONNECT_RESPONSE` (2): Connection establishment response
- `DATA` (3): Encapsulated TCP data
- `FRAGMENT` (4): Fragmented packet
- `ACK` (5): Acknowledgment
- `CLOSE` (6): Close connection

### Fragmentation

Large packets are automatically fragmented:
- Maximum ICMP payload: 65,507 bytes
- Maximum tunnel data per packet: ~65,479 bytes
- Automatic reassembly with timeout cleanup

### iptables Rules

The client automatically sets up these rules:

```bash
# Redirect outgoing TCP to local proxy
iptables -t nat -A OUTPUT -p tcp -j DNAT --to-destination 127.0.0.1:8080

# Allow traffic to proxy
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT

# Masquerade proxy responses
iptables -t nat -A POSTROUTING -p tcp -s 127.0.0.1 --sport 8080 -j SNAT --to-source 0.0.0.0
```

## Security Considerations

⚠️ **This is for academic/research purposes only!**

- ICMP tunneling is detectable by advanced firewalls
- No encryption is implemented
- Use only in controlled environments
- Not suitable for production security applications

## Troubleshooting

### Common Issues

1. **Permission denied errors:**
   - Ensure you're running as root: `sudo uv run client <server-ip>`

2. **iptables errors:**
   - Check if iptables is available: `which iptables`
   - Verify kernel modules are loaded: `lsmod | grep iptable`

3. **ICMP blocked:**
   - Some networks block ICMP - this tunnel won't work in such environments

4. **Connection timeouts:**
   - Check server is reachable: `ping <server-ip>`
   - Verify ICMP ID matches between client and server

### Debug Mode

For debugging, you can enable verbose logging by setting the log level to DEBUG:

```bash
# Client with debug logging
sudo uv run client 192.168.1.100 --log-level DEBUG

# Server with debug logging
sudo uv run server --log-level DEBUG

# Save debug logs to file
sudo uv run client 192.168.1.100 --log-level DEBUG --log-file tunnel.log
```

### Debug Script

A comprehensive debug script is provided to test individual components:

```bash
# Run all debug tests
uv run debug.py

# Run specific tests
uv run debug.py --test packet      # Test packet handling
uv run debug.py --test connection  # Test connection management
uv run debug.py --test utils       # Test utility functions
uv run debug.py --test network     # Test network connectivity

# Debug script with custom log level
uv run debug.py --log-level DEBUG --log-file debug.log
```

The debug script tests:
- **Packet Handler**: Packet creation, parsing, fragmentation, and reassembly
- **Connection Manager**: Connection lifecycle, state management, cleanup
- **Utilities**: IP/port validation, address parsing, checksum calculation
- **Network**: DNS resolution, connectivity tests

### Debug Logging Features

The tunnel includes comprehensive debug logging throughout:

- **Packet Processing**: Detailed logging of packet creation, parsing, and fragmentation
- **Connection Management**: Connection lifecycle events and state changes
- **Network Operations**: Socket operations, ICMP packet handling
- **iptables Management**: Rule creation, modification, and cleanup
- **Error Handling**: Detailed error messages with context
- **Performance Metrics**: Packet counts, connection statistics

Debug logs help identify:
- Packet loss or corruption
- Connection establishment issues
- Network connectivity problems
- iptables rule conflicts
- Performance bottlenecks

## Performance

- **Latency**: Adds ~1-5ms overhead per packet
- **Throughput**: Limited by ICMP packet rate and size
- **CPU**: Moderate overhead from packet processing
- **Memory**: Minimal memory usage with connection cleanup

## Limitations

- Linux-only (uses Linux-specific APIs)
- Requires root privileges
- ICMP rate limiting may affect performance
- No encryption or authentication
- Limited to IPv4

## Development

### Project Structure

```
tcp-over-icmp/
├── client/                 # Client-side code
│   ├── main.py            # Main client entry point
│   ├── tunnel_client.py   # Tunnel client implementation
│   └── iptables_manager.py # iptables management
├── server/                 # Server-side code
│   ├── main.py            # Main server entry point
│   └── tunnel_server.py   # Tunnel server implementation
├── shared/                 # Shared code
│   └── src/shared/
│       ├── packet_handler.py    # Packet encapsulation/decapsulation
│       ├── connection_manager.py # Connection tracking
│       └── utils.py             # Utility functions
└── README.md              # This file
```

### Building

```bash
# Install dependencies
uv sync

# Run tests (if available)
uv run test

# Build (if needed)
uv build
```

## License

This project is for academic purposes only. Use responsibly and only in controlled environments.

## Contributing

This is an academic project. Feel free to fork and experiment, but remember this is for educational purposes only.

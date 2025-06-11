# TCP-over-ICMP Tunnel

A transparent TCP-over-ICMP tunnel implementation for bypassing firewalls that block TCP but allow ICMP traffic.

## Requirements

### Python Dependencies

Install dependencies:
```bash
uv sync --all-packages
```

### System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
# install packages for NetFilterQueue
sudo apt install build-essential libnetfilter-queue-dev
# install uv - python version and package manager
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## Usage

if uv was installed using the command above it cannot be used by other users (sudo included...)
so we'll use the python from the virtual environment uv created for us

### Server Setup

1. Run the server on a machine outside the firewall:
```bash
sudo .venv/bin/python server.py --debug
```

2. Optional arguments:
```bash
sudo .venv/bin/python server.py --bind-ip 0.0.0.0 --debug
```

### Client Setup

1. Run the client on the machine behind the firewall:
```bash
sudo .venv/bin/python client.py SERVER_IP --debug
```

2. Optional arguments:
```bash
sudo .venv/bin/python client.py SERVER_IP --queue-num 0 --debug
```

### Testing

Once both server and client are running:

```bash
# Test with curl (should work through the tunnel)
curl http://httpbin.org/get

# Test with wget
wget -O - http://httpbin.org/ip

# Test with browser - just browse normally
firefox http://httpbin.org
```

## How It Works

### Client Side
1. **Packet Interception**: Uses iptables NFQUEUE to intercept outgoing TCP packets
2. **Encapsulation**: Wraps TCP data in custom ICMP echo request packets
3. **Tunneling**: Sends ICMP packets to the server
4. **Response Injection**: Receives ICMP responses and injects TCP packets back into the network stack

### Server Side
1. **ICMP Reception**: Listens for special ICMP packets from clients
2. **TCP Forwarding**: Establishes real TCP connections to target servers
3. **Data Relay**: Forwards data between client tunnel and target servers
4. **Response Tunneling**: Sends responses back via ICMP echo replies

### Protocol Design

**ICMP Tunnel Header (14 bytes):**
```
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
|          Connection ID (4 bytes)                      |
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
|          Sequence Number (4 bytes)                   |
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
|          Acknowledgment Number (4 bytes)             |  
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
|     Flags (2 bytes)     |    Data Length (2 bytes)   |
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
|                    TCP Payload Data                   |
|                     (variable)                        |
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
```

## Security Considerations

⚠️ **Warning**: This tool is for educational and legitimate testing purposes only.

- Requires root privileges on both client and server
- May be detected by advanced firewalls that analyze ICMP traffic patterns  
- Does not provide encryption - consider using with VPN for secure tunneling
- Server should be properly secured as it accepts connections from clients

## Limitations

- Currently hardcoded to tunnel HTTP traffic to `httpbin.org` (server-side)
- No authentication between client and server
- Basic error handling - production use would need more robust error recovery
- No traffic shaping or rate limiting
- Single-threaded packet processing may limit performance

## Troubleshooting

### Permission Errors
```bash
# Make sure you're running as root
sudo python3 client.py SERVER_IP
sudo python3 server.py
```

### iptables Issues
```bash
# Check current iptables rules
sudo iptables -t mangle -L OUTPUT -n

# Manually clear rules if needed
sudo iptables -t mangle -F OUTPUT
```

### Connection Issues
```bash
# Test basic ICMP connectivity
ping SERVER_IP

# Check if ICMP is being blocked
sudo tcpdump -i any icmp

# Monitor tunnel traffic
sudo tcpdump -i any 'icmp and host SERVER_IP'
```

### Debug Mode
Run both client and server with `--debug` flag for verbose logging:
```bash
sudo python3 server.py --debug
sudo python3 client.py SERVER_IP --debug
```

## File Structure

```
tunnel/
├── shared.py      # Shared protocol and utilities
├── client.py      # Tunnel client (runs behind firewall)  
├── server.py      # Tunnel server (runs outside firewall)
├── requirements.txt
└── README.md
```

## Advanced Usage

### Custom Target Configuration

To modify the server to connect to different targets, edit the `handle_syn` method in `server.py`:

```python
# Change these lines in server.py
target_host = "your-target-server.com"
target_port = 443  # or whatever port you need
```

### Multiple Queue Numbers

If you need to run multiple tunnel instances:

```bash
# Client
sudo python3 client.py SERVER_IP --queue-num 1

# Server (no change needed - it handles all clients)
sudo python3 server.py
```

### Port-Specific Tunneling

Modify iptables rules in `client.py` to tunnel specific ports:

```python
# In setup_iptables_rules method, modify:
f"iptables -t mangle -A OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num {self.queue_num}",
```

## Legal Notice

This software is provided for educational and authorized testing purposes only. Users are responsible for complying with all applicable laws and regulations. Unauthorized network penetration or bypassing security controls may be illegal in your jurisdiction.
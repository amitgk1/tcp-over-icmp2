# TCP-over-ICMP Tunnel (Minimal Proof-of-Concept)

This project implements a basic TCP-over-ICMP tunnel using Python, `asyncio`, `scapy`, and `netfilterqueue`. It's a minimal implementation focused on demonstrating the core concepts of encapsulating TCP within ICMP and redirecting traffic.

**IMPORTANT:** This is a minimal proof-of-concept. It greatly simplifies TCP state management (sequence numbers, ACKs, window sizes, retransmissions, out-of-order delivery) and error handling. It's intended as a starting point for a more robust solution.

## Prerequisites

1.  **Python 3.8+**
2.  **Required Python Libraries:**
    ```bash
    pip install scapy python-netfilterqueue
    ```
3.  **Root Privileges:** Both the client and server scripts require `root` privileges to:
    *   Set `iptables` rules.
    *   Create raw sockets (for sending/receiving ICMP).
    *   Bind to NetfilterQueue.

## Setup

### 1. Configure IPs

*   **Server:** Needs a publicly accessible IP address. Let's call it `SERVER_PUBLIC_IP`.
*   **Client:** Needs to know `SERVER_PUBLIC_IP`.

**Edit `client.py`:**
```python
SERVER_IP = "YOUR_SERVER_PUBLIC_IP" # E.g., "203.0.113.42"
```

### 2. `iptables` Rules (Required on both Client and Server)

#### On the Client Machine:

These rules redirect outgoing TCP traffic to your local client proxy.
**Run these commands as root:**

```bash
# Redirect HTTP (port 80) traffic to client.py's listen port (8080)
sudo iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports 8080

# (Optional) Redirect HTTPS (port 443) traffic too
# sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports 8080

# Verify the rule (look for your REDIRECT rule)
sudo iptables -t nat -nvL OUTPUT --line-numbers
```

**To remove the rules (if needed):**
First, list the rules with line numbers: `sudo iptables -t nat -nvL OUTPUT --line-numbers`
Then delete using the chain name and line number: `sudo iptables -t nat -D OUTPUT <line_number>`

#### On the Server Machine:

These rules divert incoming ICMP Echo Requests (from your client tunnel) to `NFQUEUE 0` and prevent the kernel from sending an automatic reply.

**Run these commands as root:**

```bash
# Add a rule to divert incoming ICMP Echo Requests to NFQUEUE 0
# IMPORTANT: This rule should be placed before any ACCEPT/DROP rules for ICMP if they exist.
# Example: -A INPUT -p icmp --icmp-type echo-request -j NFQUEUE --queue-num 0
sudo iptables -A INPUT -p icmp --icmp-type 8 -j NFQUEUE --queue-num 0

# Verify the rule
sudo iptables -nvL INPUT --line-numbers
```

**To remove the rule (if needed):**
First, list the rules with line numbers: `sudo iptables -nvL INPUT --line-numbers`
Then delete using the chain name and line number: `sudo iptables -D INPUT <line_number>`

## Running the Tunnel

### 1. Start the Server

On your server machine (with public IP), run:

```bash
sudo python3 server.py
```

You should see output indicating that the server is initializing and starting its NFQUEUE listener.

### 2. Start the Client

On your client machine (behind the firewall), run:

```bash
sudo python3 client.py
```

You should see output indicating that the client is listening for redirected TCP traffic.

## Testing

Once both are running:

*   **From the client machine:** Try to access a website using HTTP (e.g., `curl http://example.com` or open a web browser).
*   **Observe logs:**
    *   The client should show messages about local connections being redirected and data being sent via ICMP.
    *   The server should show messages about receiving ICMP, connecting to the remote target, and sending data back via ICMP.
*   **Wireshark (Highly Recommended):** Capture traffic on both the client (e.g., `lo` interface for redirected TCP, and your main interface for ICMP) and the server (main interface for ICMP and external TCP). This will be invaluable for debugging the encapsulated packets and TCP state.

## Limitations of this Minimal Implementation

*   **Simplified TCP State Management:**
    *   Sequence and acknowledgment numbers are largely ignored or simplified, which will cause issues for complex TCP flows (e.g., large file transfers, connections that encounter packet loss).
    *   TCP flags (PSH, FIN, RST, ACK) are handled very basically. Full handling is required for robustness.
    *   No window size management.
    *   No retransmission logic at the tunnel layer (relies on underlying TCP).
*   **No Tunnel-Layer Reliability:** ICMP is unreliable. If an ICMP packet is lost, the underlying TCP protocol will eventually time out and retransmit, but the tunnel itself doesn't actively ensure delivery of its encapsulated segments.
*   **No Fragmentation at Tunnel Layer:** Relies on IP fragmentation if the tunneled TCP segment plus custom header exceeds the MTU, which might be blocked by some firewalls.
*   **Basic Error Handling:** Lacks robust error recovery, timeouts, and resource cleanup for all scenarios.
*   **Single Client IP:** Server doesn't track multiple clients.
*   **No NAT/Multiple App Support:** While `iptables REDIRECT` is multi-app, the internal TCP state tracking is rudimentary.

This code provides the skeletal framework. Building a robust tunnel requires fleshing out the TCP state machine and reliability significantly.
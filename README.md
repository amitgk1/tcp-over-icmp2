client iptables
```bash
# 1) queue all outgoing TCP (NEW or ESTABLISHED), except localhost, into NFQUEUE=1
iptables -t mangle -A OUTPUT \
    -p tcp ! -d 127.0.0.0/8 \
    -m conntrack --ctstate NEW,ESTABLISHED \
    -j NFQUEUE --queue-num 1

# 2) queue incoming ICMP echo-replies back into NFQUEUE=1
iptables -t mangle -A PREROUTING \
    -p icmp --icmp-type echo-reply \
    -j NFQUEUE --queue-num 1
```

server

for ip forwarding 🤷‍♂️
```bash
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

iptables rules:
```bash
# 1) incoming ICMP echo-requests → NFQUEUE 1
iptables -t mangle -A PREROUTING \
    -p icmp --icmp-type echo-request \
    -j NFQUEUE --queue-num 1

# 2) forwarded TCP replies back to the client‐IP → NFQUEUE 1
#    (replace 10.0.0.0/24 with the client’s private subnet)
iptables -t mangle -A PREROUTING \
    -p tcp -d 10.0.0.0/24 \
    -j NFQUEUE --queue-num 1
```
# FPTN VPN Server — Installation Guide

FPTN is a VPN technology built from the ground up to provide secure, censorship- and block-resistant connections that can bypass censorship and network filtering.

- Website: https://fptn.org
- GitHub: https://github.com/batchar2/fptn
- Telegram chat: https://t.me/fptn_project

---

## Key features

- **Full IP‑level tunneling (L3 VPN)**  
  FPTN creates a true Layer‑3 tunnel using a TUN interface. All IPv4 and IPv6 traffic is supported and routed transparently. On the client side, traffic can be selectively routed through the tunnel using split‑tunneling based on DNS resolution.
- **Custom transport protocol over HTTPS**  
  Raw IP packets are serialized into protobuf messages and transported through a secure WebSocket connection. This forms a lightweight, fully controllable transport layer independent of classic VPN protocols.
- **TLS stack based on BoringSSL**  
  TLS is built on top of BoringSSL, the same library used by Chrome.
- **Stealth client identification**  
  Legitimate clients are recognized directly at the TLS level using a modified `session_id` field. This allows the server to authenticate clients without exposing a visible VPN protocol or additional negotiation phase.
- **Advanced traffic camouflage**  
  The client supports SNI spoofing, TLS handshake obfuscation, and a “reality mode” where the connection initially behaves like a real HTTPS session before switching to the VPN tunnel. This significantly complicates DPI classification.
- **Indistinguishable server behavior**  
  If an incoming connection does not match the expected TLS fingerprint, the server transparently proxies traffic to the SNI domain. Externally, the server behaves like a normal HTTPS website and does not reveal that a VPN service is running.
- **Traffic shaping and access control**  
  Per‑user bandwidth limits and policies are enforced on the server using a Leaky Bucket–based traffic shaper. This prevents individual clients from exhausting shared resources.
- **Unwanted traffic filtering**  
  Built‑in packet inspection detects BitTorrent signatures and blocks such traffic to comply with hosting policies and reduce abuse.
- **Management, clustering, and monitoring**  
  The server exposes a REST API protected by JWT for user and system management. Distributed master/slave architecture is supported. Operational metrics are exported to Prometheus and can be visualized in Grafana. A Telegram bot is available for basic integration and notifications.

---


## 1. Create Working Directory

Create a folder to store all server files and configurations. This keeps your setup organized.

```bash
mkdir fptn-server && cd fptn-server
```




## 2. Create docker-compose.yml


```yaml
services:
  fptn-server:
    restart: unless-stopped
    image: fptnvpn/fptn-vpn-server:latest
    privileged: true
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
      - NET_RAW
      - SYS_ADMIN
      - SYS_RESOURCE
    sysctls:
      net.ipv4.ip_local_port_range: "1024 65535"
    ulimits:
      nproc:
        soft: 524288
        hard: 524288
      nofile:
        soft: 524288
        hard: 524288
      memlock:
        soft: 524288
        hard: 524288
    devices:
      - /dev/net/tun:/dev/net/tun
    ports:
      - "${FPTN_PORT}:443/tcp"
    volumes:
      - ./fptn-server-data:/etc/fptn
    environment:
      - ENABLE_DETECT_PROBING=${ENABLE_DETECT_PROBING}
      - DEFAULT_PROXY_DOMAIN=${DEFAULT_PROXY_DOMAIN}
      - ALLOWED_SNI_LIST=${ALLOWED_SNI_LIST}
      - DISABLE_BITTORRENT=${DISABLE_BITTORRENT}
      - PROMETHEUS_SECRET_ACCESS_KEY=${PROMETHEUS_SECRET_ACCESS_KEY}
      - USE_REMOTE_SERVER_AUTH=${USE_REMOTE_SERVER_AUTH}
      - REMOTE_SERVER_AUTH_HOST=${REMOTE_SERVER_AUTH_HOST}
      - REMOTE_SERVER_AUTH_PORT=${REMOTE_SERVER_AUTH_PORT}
      - MAX_ACTIVE_SESSIONS_PER_USER=${MAX_ACTIVE_SESSIONS_PER_USER}
      - SERVER_EXTERNAL_IPS=${SERVER_EXTERNAL_IPS}
      - MTU_SIZE=${MTU_SIZE:-1500}
      - USING_DNS_SERVER=${USING_DNS_SERVER:-dnsmasq}
      - DNS_IPV6_ENABLE=${DNS_IPV6_ENABLE:-false}
      - DNS_IPV4_PRIMARY=${DNS_IPV4_PRIMARY:-8.8.8.8}
      - DNS_IPV4_SECONDARY=${DNS_IPV4_SECONDARY:-8.8.4.4}
      - DNS_IPV6_PRIMARY=${DNS_IPV6_PRIMARY:-2001:4860:4860::8888}
      - DNS_IPV6_SECONDARY=${DNS_IPV6_SECONDARY:-2001:4860:4860::8844}
    healthcheck:
      test: ["CMD", "sh", "-c", "pgrep fptn-server"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - fptn-network
networks:
  fptn-network:
    driver: bridge
    enable_ipv6: true
    ipam:
      config:
        - subnet: dead:beef:cafe::/48
          gateway: dead:beef:cafe::1
        - subnet: 192.168.200.0/24
          gateway: 192.168.200.1
```

## 3. Create `.env` file and configure server options.


```bash
# ============================================
# FPTN SERVER
# ============================================
FPTN_PORT=443

# Comma-separated list of server's public IPv4 addresses.
# IMPORTANT: Set all server public IPs to prevent proxy loops when server receives requests to itself
# Example: SERVER_EXTERNAL_IPS=1.2.3.4,5.6.7.8
SERVER_EXTERNAL_IPS=

# Enable detection of probing attempts (accepted values: true or false)
ENABLE_DETECT_PROBING=true

# Default domain where non-VPN client traffic will be redirected
# When someone scans your server (not using VPN), their connection will be forwarded to this domain instead
DEFAULT_PROXY_DOMAIN=rutube.ru

# Comma-separated list of allowed website domains for non-VPN clients
# This acts like a "whitelist" of websites that scanning bots are allowed to reach
# Behavior logic:
#   - List is empty (default): allows ALL domains, proxy all non-VPN traffic to the SNI in the TLS-handshake
#   - List is NOT empty: use as whitelist:
#       - Client SNI in list -> proxy to client's SNI
#       - Client SNI not in list -> proxy to --default-proxy-domain
# Domain matching includes all subdomains:
#   - If "example.com" is in the list, it will match:
#       - example.com (exact match)
#       - www.example.com
#       - api.example.com
#       - any.other.sub.example.com
# Examples:
#   ALLOWED_SNI_LIST=example.com,test.org
#   This allows: example.com, test.org and ALL their subdomains
# ALLOWED_SNI_LIST=vprok.ru,vk.com,perekrestok.ru,x5.ru,yandex.ru,yandex.com,max.ru,alfabank.ru,ozone.ru,rutube.ru
ALLOWED_SNI_LIST=

# Block BitTorrent traffic to prevent abuse (accepted values: true or false)
DISABLE_BITTORRENT=true

# Set the USE_REMOTE_SERVER_AUTH variable to true if you need to
# redirect requests to a master FPTN server for authorization.
# This is used for cluster operations.
USE_REMOTE_SERVER_AUTH=false
# Specify the remote FPTN server's host address for authorization.
# This should be the IP address or domain name of the server.
REMOTE_SERVER_AUTH_HOST=
# Specify the port of the remote FPTN server for authorization.
# The default is port 443 for secure HTTPS connections.
REMOTE_SERVER_AUTH_PORT=443

# Set a secret key to allow Prometheus to access the server's statistics.
# This key must be alphanumeric (letters and numbers only) and must not include spaces or special characters.
PROMETHEUS_SECRET_ACCESS_KEY=

# Maximum number of active sessions allowed per VPN user
MAX_ACTIVE_SESSIONS_PER_USER=3

# ============================================
# DNS SERVER
# ============================================
# Choose which DNS server will be used for the VPN clients
# Available options:
#   - dnsmasq : Lightweight, caching DNS forwarder
#   - unbound : Recursive, validating DNS resolver
# Default: dnsmasq
USING_DNS_SERVER=dnsmasq

# Enable/disable IPv6 DNS resolution
# Values: true, false
# Default: false
DNS_IPV6_ENABLE=false

# DNS SETTINGS IPv4
# These settings are used ONLY when USING_DNS_SERVER=dnsmasq
DNS_IPV4_PRIMARY=8.8.8.8
DNS_IPV4_SECONDARY=8.8.4.4

# DNS SETTINGS IPv6
# These settings are used ONLY when USING_DNS_SERVER=dnsmasq
DNS_IPV6_PRIMARY=2001:4860:4860::8888
DNS_IPV6_SECONDARY=2001:4860:4860::8844

```

*SERVER_EXTERNAL_IPS* (REQUIRED) - Comma-separated list of your server's public IPv4 addresses. Example: 1.2.3.4,5.6.7.8



## 4. Create SSL certificates

Create a private key and self-signed certificate for HTTPS. Required for secure client connections.

```
docker compose run --rm fptn-server sh -c "cd /etc/fptn && openssl genrsa -out server.key 2048"

docker compose run --rm fptn-server sh -c "cd /etc/fptn && openssl req -new -x509 -key server.key -out server.crt -days 365"

docker compose run --rm fptn-server sh -c "openssl x509 -noout -fingerprint -md5 -in /etc/fptn/server.crt | cut -d'=' -f2 | tr -d ':' | tr 'A-F' 'a-f' | xargs -I {} echo 'MD5 Fingerprint: {}'"
```


## 5. Start server

Launch the VPN server container in detached mode.

```bash
docker compose up -d
```

## 6. Check Server Status

Ensure the container is running and healthy.

```bash
docker compose ps
```


## 7. Add a VPN User

Create a VPN user that clients will use to connect. You can set a per-user bandwidth limit.

```bash
docker compose exec fptn-server fptn-passwd --add-user <username> --bandwidth 100
```

- Replace `<username>` with the desired username.
- The `--bandwidth` option sets the maximum connection speed in Mbps for this user.



## 8. Generate a Connection Token

Generate a token for the VPN client. This token includes the username, password, and server IP, and is used in the client app to connect.

```
docker compose run --rm fptn-server token-generator --user <username> --password <password> --server-ip <server_public_ip> --port <server_public_port>
```

Replace:
- `<username>` — the VPN username you created
- `<password>` — the password for this user
- `<server_public_ip>` — the public IP address of your VPN server
- `<server_public_port>` — port number for the VPN server (default: 443, range: 1-65535)


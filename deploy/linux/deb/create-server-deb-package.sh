#!/usr/bin/env bash

# Function to print usage
print_usage() {
    echo "Usage: $0 <fptn-server-path> <fptn-passwd-path> <version>"
    exit 1
}

if [ "$#" -ne 3 ]; then
    print_usage
fi

SERVER_BIN="$1"
PASSWD_BIN="$2"
VERSION="$3"

MAINTAINER="FPTN Project"

OS_NAME=$(lsb_release -i | awk -F':\t' '{print $2}' | tr '[:upper:]' '[:lower:]')
OS_VERSION=$(lsb_release -r | awk -F':\t' '{print $2}')

SERVER_TMP_DIR=$(mktemp -d -t fptn-server-XXXXXX)

mkdir -p "$SERVER_TMP_DIR/DEBIAN"
mkdir -p "$SERVER_TMP_DIR/usr/bin"
mkdir -p "$SERVER_TMP_DIR/etc/fptn"
mkdir -p "$SERVER_TMP_DIR/lib/systemd/system"

# Copy server files
cp "$SERVER_BIN" "$SERVER_TMP_DIR/usr/bin/"
chmod 755 "$SERVER_TMP_DIR/usr/bin/$(basename "$SERVER_BIN")"
cp "$PASSWD_BIN" "$SERVER_TMP_DIR/usr/bin/"
chmod 755 "$SERVER_TMP_DIR/usr/bin/$(basename "$PASSWD_BIN")"

# Create server configuration file
cat <<EOL > "$SERVER_TMP_DIR/etc/fptn/server.conf"
# Configuration for fptn server

OUT_NETWORK_INTERFACE=

# KEYS
SERVER_KEY=
SERVER_CRT=

PORT=443
TUN_INTERFACE_NAME=fptn0

# MTU size of the VPN tunnel interface
# Leave empty to use the built-in default
MTU_SIZE=1420

# Path to the file with VPN users (created by fptn-passwd)
# Leave empty to use the default (/etc/fptn/users.list)
USERFILE=/etc/fptn/users.list

# Enable detection of probing attempts (experimental; accepted values: true or false)
ENABLE_DETECT_PROBING=false

# Default domain where non-VPN client traffic will be redirected
# When someone scans your server (not using VPN), their connection will be forwarded to this domain instead
DEFAULT_PROXY_DOMAIN=cdnvideo.com

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
ALLOWED_SNI_LIST=

# Block BitTorrent traffic to prevent abuse (accepted values: true or false)
DISABLE_BITTORRENT=true

# Optional: path to a file with extra domains to block, one per line
# ('#' starts a comment). Traffic to the addresses these domains and their
# subdomains resolve to is dropped. The file extends the built-in list.
# Empty (default) uses only the built-in list.
DOMAIN_BLACKLIST_FILE=

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

# Public IPv4 addresses of this VPN server (comma-separated).
# Used to prevent proxy loops when clients connect.
# Example: 1.2.3.4,5.6.7.8
SERVER_EXTERNAL_IPS=

EOL

# Create systemd service file for server
cat <<EOL > "$SERVER_TMP_DIR/lib/systemd/system/fptn-server.service"
[Unit]
Description=FPTN Server Service
After=network.target

[Service]
EnvironmentFile=/etc/fptn/server.conf
ExecStart=/usr/bin/$(basename "$SERVER_BIN") \
  --server-key=\${SERVER_KEY} \
  --server-crt=\${SERVER_CRT} \
  --out-network-interface=\${OUT_NETWORK_INTERFACE} \
  --server-port=\${PORT} \
  --enable-detect-probing=\${ENABLE_DETECT_PROBING} \
  --default-proxy-domain=\${DEFAULT_PROXY_DOMAIN} \
  --allowed-sni-list=\${ALLOWED_SNI_LIST} \
  --tun-interface-name=\${TUN_INTERFACE_NAME} \
  --mtu-size=\${MTU_SIZE} \
  --userfile=\${USERFILE} \
  --disable-bittorrent=\${DISABLE_BITTORRENT} \
  --domain-blacklist-file=\${DOMAIN_BLACKLIST_FILE} \
  --prometheus-access-key=\${PROMETHEUS_SECRET_ACCESS_KEY} \
  --use-remote-server-auth=\${USE_REMOTE_SERVER_AUTH} \
  --remote-server-auth-host=\${REMOTE_SERVER_AUTH_HOST} \
  --remote-server-auth-port=\${REMOTE_SERVER_AUTH_PORT} \
  --max-active-sessions-per-user=\${MAX_ACTIVE_SESSIONS_PER_USER} \
  --server-external-ips=\${SERVER_EXTERNAL_IPS}
Restart=always
WorkingDirectory=/etc/fptn
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOL

# Create control file for server package
INSTALLED_SIZE=$(du -s "$SERVER_TMP_DIR/usr" | cut -f1)
cat <<EOL > "$SERVER_TMP_DIR/DEBIAN/control"
Package: fptn-server
Version: ${VERSION}
Architecture: $(dpkg --print-architecture)
Maintainer: ${MAINTAINER}
Installed-Size: ${INSTALLED_SIZE}
Depends: iptables, iproute2, net-tools
Section: admin
Replaces: fptn-server
Conflicts: fptn-server
Provides: fptn-server
Priority: optional
Description: fptn server
EOL


# Create preinst file
cat <<EOL > "$SERVER_TMP_DIR/DEBIAN/preinst"
#!/bin/bash

if [ -f /etc/fptn/server.conf ]; then
    cp /etc/fptn/server.conf "/etc/fptn/server.conf.backup.\$(date +'%Y-%m-%d__%H-%M-%S')"
fi
EOL
chmod 755 "$SERVER_TMP_DIR/DEBIAN/preinst"


# Create postinst file
cat <<EOL > "$SERVER_TMP_DIR/DEBIAN/postinst"
#!/bin/bash

chown root:root /etc/fptn/server.conf 2>/dev/null  || true
EOL
chmod 755 "$SERVER_TMP_DIR/DEBIAN/postinst"


cat <<EOL > "$SERVER_TMP_DIR/DEBIAN/prerm"
#!/bin/bash

systemctl daemon-reload 2>/dev/null || echo "Failed to reload"
systemctl stop fptn-server 2>/dev/null || echo "Failed to stop"
EOL
chmod 755 "$SERVER_TMP_DIR/DEBIAN/prerm"


cat <<EOL > "$SERVER_TMP_DIR/DEBIAN/postrm"
#!/bin/bash

if [ "\$1" != "upgrade" ]; then
    systemctl disable fptn-server.service 2>/dev/null || echo "Failed to disable"
    rm -f /lib/systemd/system/fptn-server.service 2>/dev/null || echo "Failed to remove"
fi
EOL
chmod 755 "$SERVER_TMP_DIR/DEBIAN/postrm"

# Build the Debian package
dpkg-deb --build "$SERVER_TMP_DIR" "fptn-server-${VERSION}-${OS_NAME}${OS_VERSION}-$(dpkg --print-architecture).deb"

# Clean up temporary directory
rm -rf "$SERVER_TMP_DIR"


chmod 644 "fptn-server-${VERSION}-${OS_NAME}${OS_VERSION}-$(dpkg --print-architecture).deb"

echo "Server Debian package created successfully."
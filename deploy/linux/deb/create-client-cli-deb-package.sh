#!/usr/bin/env bash

# Function to print usage
print_usage() {
    echo "Usage: $0 <fptn-client-cli-path> <version>"
    exit 1
}

# Check if the correct number of arguments are provided
if [ "$#" -ne 2 ]; then
    print_usage
fi

CLIENT_CLI="$1"
VERSION="$2"
MAINTAINER="FPTN Project"

OS_NAME=$(lsb_release -i | awk -F':\t' '{print $2}' | tr '[:upper:]' '[:lower:]')
OS_VERSION=$(lsb_release -r | awk -F':\t' '{print $2}')

CLIENT_TMP_DIR=$(mktemp -d -t fptn-client-cli-XXXXXX)

mkdir -p "$CLIENT_TMP_DIR/DEBIAN"
mkdir -p "$CLIENT_TMP_DIR/usr/bin"
mkdir -p "$CLIENT_TMP_DIR/etc/fptn-client"
mkdir -p "$CLIENT_TMP_DIR/lib/systemd/system"

# Copy client binary
cp "$CLIENT_CLI" "$CLIENT_TMP_DIR/usr/bin/"
chmod 755 "$CLIENT_TMP_DIR/usr/bin/$(basename "$CLIENT_CLI")"


# Create client configuration file
cat <<EOL > "$CLIENT_TMP_DIR/etc/fptn-client/client.conf"
# FPTN Client Configuration
# =========================


# Required: Authentication token for server access
ACCESS_TOKEN=


# Required: Domain name used for SNI (Server Name Indication)
# This should be a popular, non-blocked domain in your region
# Example: rutube.ru, youtube.com, cloudflare.com
SNI=rutube.ru


# Optional: Connect to specific server instead of auto-selecting fastest
# Name matching is case-insensitive
PREFERRED_SERVER=


# Optional: Bind to specific network interface
# Leave empty to use default interface. Examples: eth0, wlan0, tun0
NETWORK_INTERFACE=


# Optional: Specify the gateway IPv4 (e.g., router IPv4)
GATEWAY_IP=

# Optional: Specify the gateway IPv6 (e.g., router IPv6)
GATEWAY_IPv6=

# Censorship Bypass Settings
# Optional: Method to bypass censorship mechanisms
# Available options:
#   - sni-spoofing              - SNI spoofing (default fingerprint)
#   - obfuscation               - Masks traffic as regular HTTPS using TLS obfuscation
#   - sni-spoofing-chrome-149   - SNI spoofing with Chrome 149 browser fingerprint
#   - sni-spoofing-chrome-148   - SNI spoofing with Chrome 148 browser fingerprint
#   - sni-spoofing-chrome-147   - SNI spoofing with Chrome 147 browser fingerprint
#   - sni-spoofing-chrome-146   - SNI spoofing with Chrome 146 browser fingerprint
#   - sni-spoofing-chrome-145   - SNI spoofing with Chrome 145 browser fingerprint
#   - sni-spoofing-firefox-151  - SNI spoofing with Firefox 151 browser fingerprint
#   - sni-spoofing-firefox-150  - SNI spoofing with Firefox 150 browser fingerprint
#   - sni-spoofing-firefox-149  - SNI spoofing with Firefox 149 browser fingerprint
#   - sni-spoofing-yandex-26-3  - SNI spoofing with Yandex Browser 26 fingerprint
#   - sni-spoofing-yandex-25    - SNI spoofing with Yandex Browser 25 fingerprint
#   - sni-spoofing-yandex-24    - SNI spoofing with Yandex Browser 24 fingerprint
#   - sni-spoofing-safari-26-5  - SNI spoofing with Safari 26 browser fingerprint
#   - sni-spoofing-safari-26-4  - SNI spoofing with Safari 26 browser fingerprint
BYPASS_METHOD=sni-spoofing


# Blacklist domains - always blocked regardless of other settings
# Completely block access to the main domain AND all its subdomains
# Format: domain:<domain_name>[,domain:<domain_name>...]
# Example: domain:ria.ru blocks ria.ru and all *.ria.ru sites
BLACKLIST_DOMAINS=domain:solovev-live.ru,domain:ria.ru,domain:tass.ru,domain:1tv.ru,domain:ntv.ru,domain:rt.com


# Networks that always bypass VPN (highest priority)
# Traffic to these networks never uses VPN, regardless of other settings
# Format: CIDR notation, comma-separated
# Default: Private networks (10.0.0.0/8,172.16.0.0/12,192.168.0.0/16) bypass VPN
EXCLUDE_TUNNEL_NETWORKS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16


# Networks that always use VPN (highest priority)
# Traffic to these networks always uses VPN, regardless of other settings
# Format: CIDR notation, comma-separated
# Empty by default - no networks forced through VPN
INCLUDE_TUNNEL_NETWORKS=


# Split Tunneling Settings
# Enable split tunneling feature
# When enabled, traffic routing is controlled by SPLIT_TUNNEL_MODE and domain/network lists
# true:  Enable split tunneling - configure routing with SPLIT_TUNNEL_MODE below
# false: Disable split tunneling - all traffic goes through VPN tunnel
ENABLE_SPLIT_TUNNEL=true


# Split tunneling mode - defines traffic routing strategy
# exclude: Route specified domains/networks directly, all other traffic through VPN
#          Use case: Local/trusted sites bypass VPN for better performance
# include: Route only specified domains/networks through VPN, all other traffic directly
#          Use case: Protect only sensitive/blocked sites with VPN
SPLIT_TUNNEL_MODE=exclude


# Domains for split tunneling - traffic classification based on SPLIT_TUNNEL_MODE
# Format: domain:<domain_name>[,domain:<domain_name>...]
# With SPLIT_TUNNEL_MODE=exclude: These domains bypass VPN tunnel
# With SPLIT_TUNNEL_MODE=include: Only these domains use VPN tunnel
# Examples for Russia: Local sites (.ru, .su) bypass VPN, foreign sites use VPN
SPLIT_TUNNEL_DOMAINS=domain:ru,domain:su,domain:рф,domain:vk.com,domain:yandex.com,domain:userapi.com,domain:yandex.net,domain:clstorage.net

EOL


# Create systemd service file for client
cat <<EOL > "$CLIENT_TMP_DIR/lib/systemd/system/fptn-client.service"
[Unit]
Description=FPTN Client Service
After=network.target

[Service]
EnvironmentFile=/etc/fptn-client/client.conf
ExecStart=/usr/bin/$(basename "$CLIENT_CLI") \
    --access-token "\${ACCESS_TOKEN}" \
    --out-network-interface "\${NETWORK_INTERFACE}" \
    --gateway-ip "\${GATEWAY_IP}" \
    --gateway-ipv6 "\${GATEWAY_IPv6}" \
    --sni "\${SNI}" \
    --bypass-method "\${BYPASS_METHOD}" \
    --blacklist-domains "\${BLACKLIST_DOMAINS}" \
    --enable-split-tunnel=\${ENABLE_SPLIT_TUNNEL} \
    --split-tunnel-mode "\${SPLIT_TUNNEL_MODE}" \
    --split-tunnel-domains "\${SPLIT_TUNNEL_DOMAINS}" \
    --exclude-tunnel-networks "\${EXCLUDE_TUNNEL_NETWORKS}" \
    --include-tunnel-networks "\${INCLUDE_TUNNEL_NETWORKS}" \
    --preferred-server "\${PREFERRED_SERVER}"

Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOL

# Create control file for client package
INSTALLED_SIZE=$(du -s "$CLIENT_TMP_DIR/usr" | cut -f1)
cat <<EOL > "$CLIENT_TMP_DIR/DEBIAN/control"
Package: fptn-client-cli
Version: ${VERSION}
Architecture: $(dpkg --print-architecture)
Maintainer: ${MAINTAINER}
Installed-Size: ${INSTALLED_SIZE}
Depends: iptables, iproute2, net-tools
Section: admin
Replaces: fptn-client-cli
Conflicts: fptn-client-cli
Provides: fptn-client-cli
Priority: optional
Description: fptn client
EOL


# Mark the client configuration as a conffile so dpkg preserves user edits
# (token, preferred server, split-tunnel settings) across package upgrades
cat <<EOL > "$CLIENT_TMP_DIR/DEBIAN/conffiles"
/etc/fptn-client/client.conf
EOL


# Create postinst file
cat <<EOL > "$CLIENT_TMP_DIR/DEBIAN/postinst"
#!/bin/bash

systemctl daemon-reload || echo "Failed to reload"
# On upgrade, re-apply the updated unit if the service is already enabled
if systemctl is-enabled fptn-client.service >/dev/null 2>&1; then
    systemctl restart fptn-client.service || echo "Failed to restart"
fi
EOL
chmod 755 "$CLIENT_TMP_DIR/DEBIAN/postinst"


# Create prerm file
cat <<EOL > "$CLIENT_TMP_DIR/DEBIAN/prerm"
#!/bin/bash

systemctl daemon-reload || echo "Failed to reload"
systemctl stop fptn-client 2>/dev/null || echo "Failed to stop"
EOL
chmod 755 "$CLIENT_TMP_DIR/DEBIAN/prerm"


# Create postrm file
cat <<EOL > "$CLIENT_TMP_DIR/DEBIAN/postrm"
#!/bin/bash

if [ "\$1" != "upgrade" ]; then
    systemctl disable fptn-client.service 2>/dev/null || true
    rm -f /lib/systemd/system/fptn-client.service 2>/dev/null || echo "Failed to remove"
fi
EOL
chmod 755 "$CLIENT_TMP_DIR/DEBIAN/postrm"



# Build the Debian package
dpkg-deb --root-owner-group --build "$CLIENT_TMP_DIR" "fptn-client-cli-${VERSION}-${OS_NAME}${OS_VERSION}-$(dpkg --print-architecture).deb"

# Clean up temporary directories
rm -rf "$CLIENT_TMP_DIR"

echo "Client Debian package created successfully."

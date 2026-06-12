#!/usr/bin/env bash

# Function to print usage
print_usage() {
    echo "Usage: $0 <fptn-server-path> <fptn-passwd-path> <version>"
    exit 1
}

if [ "$#" -ne 3 ]; then
    print_usage
fi

SERVER_BIN=$(realpath "$1")
PASSWD_BIN=$(realpath "$2")
VERSION="$3"

if ! command -v rpmbuild &> /dev/null; then
    echo "Error: rpmbuild is not installed. Install rpm-build package."
    exit 1
fi

ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
    RPM_ARCH="x86_64"
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    RPM_ARCH="aarch64"
else
    RPM_ARCH="$ARCH"
fi

SERVER_TMP_DIR=$(mktemp -d /tmp/fptn-server-rpm-XXXXXX)
RPMBUILD_DIR="$SERVER_TMP_DIR/rpmbuild"

mkdir -p "$RPMBUILD_DIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Create server.conf
cat << 'EOF' > "$RPMBUILD_DIR/SOURCES/server.conf"
# Configuration for fptn server

OUT_NETWORK_INTERFACE=

# KEYS
SERVER_KEY=
SERVER_CRT=

PORT=443
TUN_INTERFACE_NAME=fptn0

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
EOF

# Create fptn-server.service
cat << 'EOF' > "$RPMBUILD_DIR/SOURCES/fptn-server.service"
[Unit]
Description=FPTN Server Service
After=network.target

[Service]
EnvironmentFile=/etc/fptn/server.conf
ExecStart=/usr/bin/fptn-server \
  --server-key=${SERVER_KEY} \
  --server-crt=${SERVER_CRT} \
  --out-network-interface=${OUT_NETWORK_INTERFACE} \
  --server-port=${PORT} \
  --enable-detect-probing=${ENABLE_DETECT_PROBING} \
  --default-proxy-domain=${DEFAULT_PROXY_DOMAIN} \
  --allowed-sni-list=${ALLOWED_SNI_LIST} \
  --tun-interface-name=${TUN_INTERFACE_NAME} \
  --disable-bittorrent=${DISABLE_BITTORRENT} \
  --prometheus-access-key=${PROMETHEUS_SECRET_ACCESS_KEY} \
  --use-remote-server-auth=${USE_REMOTE_SERVER_AUTH} \
  --remote-server-auth-host=${REMOTE_SERVER_AUTH_HOST} \
  --remote-server-auth-port=${REMOTE_SERVER_AUTH_PORT} \
  --max-active-sessions-per-user=${MAX_ACTIVE_SESSIONS_PER_USER} \
  --server-external-ips=${SERVER_EXTERNAL_IPS}
Restart=always
WorkingDirectory=/etc/fptn
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

# Create spec file
cat <<EOF > "$RPMBUILD_DIR/SPECS/fptn-server.spec"
Name:           fptn-server
Version:        ${VERSION}
Release:        1%{?dist}
Summary:        FPTN VPN Server
License:        GPLv3
Group:          System Environment/Daemons
Requires:       iptables, iproute, net-tools
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
BuildArch:      ${RPM_ARCH}

%description
FPTN server component.

%install
mkdir -p "%{buildroot}/usr/bin"
mkdir -p "%{buildroot}/etc/fptn"
mkdir -p "%{buildroot}/usr/lib/systemd/system"

install -m 755 "${SERVER_BIN}" "%{buildroot}/usr/bin/fptn-server"
install -m 755 "${PASSWD_BIN}" "%{buildroot}/usr/bin/fptn-passwd"
install -m 644 "${RPMBUILD_DIR}/SOURCES/server.conf" "%{buildroot}/etc/fptn/server.conf"
install -m 644 "${RPMBUILD_DIR}/SOURCES/fptn-server.service" "%{buildroot}/usr/lib/systemd/system/fptn-server.service"

%post
systemctl daemon-reload >/dev/null 2>&1 || :

%preun
if [ \$1 -eq 0 ]; then
    systemctl stop fptn-server >/dev/null 2>&1 || :
    systemctl disable fptn-server >/dev/null 2>&1 || :
fi

%postun
systemctl daemon-reload >/dev/null 2>&1 || :
if [ \$1 -ge 1 ]; then
    systemctl try-restart fptn-server >/dev/null 2>&1 || :
fi

%files
%defattr(-,root,root,-)
%dir /etc/fptn
/usr/bin/fptn-server
/usr/bin/fptn-passwd
%config(noreplace) /etc/fptn/server.conf
/usr/lib/systemd/system/fptn-server.service
EOF

rpmbuild --define "_topdir $RPMBUILD_DIR" -bb "$RPMBUILD_DIR/SPECS/fptn-server.spec"

cp "$RPMBUILD_DIR/RPMS/${RPM_ARCH}/"*.rpm .

rm -rf "$SERVER_TMP_DIR"
echo "Server RPM package created successfully."

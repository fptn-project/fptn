#!/usr/bin/env bash

print_usage() {
    echo "Usage: $0 <fptn-client-path> <icon-path> <version> <sni-source-dir>"
    exit 1
}
if [ "$#" -ne 4 ]; then
    print_usage
fi

CLIENT_GUI="$1"
CLIENT_ICON="$2"
VERSION="$3"
SNI_SOURCE_DIR="$4"

MAINTAINER="FPTN Project"
OS_NAME=$(lsb_release -i | awk -F':\t' '{print $2}' | tr '[:upper:]' '[:lower:]')
OS_VERSION=$(lsb_release -r | awk -F':\t' '{print $2}')
CLIENT_TMP_DIR=$(mktemp -d -t fptn-client-XXXXXX)

# create structure
mkdir -p "$CLIENT_TMP_DIR/DEBIAN"
mkdir -p "$CLIENT_TMP_DIR/usr/bin"
mkdir -p "$CLIENT_TMP_DIR/opt/fptn/qt6"  # Qt directory
mkdir -p "$CLIENT_TMP_DIR/opt/fptn/SNI"  # SNI directory
mkdir -p "$CLIENT_TMP_DIR/usr/share/applications"  # Directory for .desktop file
mkdir -p "$CLIENT_TMP_DIR/usr/share/icons/hicolor/512x512/apps"  # Directory for icon

# copy program
cp -v "$CLIENT_GUI" "$CLIENT_TMP_DIR/opt/fptn/fptn-client-gui"
chmod 755 "$CLIENT_TMP_DIR/opt/fptn/fptn-client-gui"

# copy SNI files
if [ -d "$SNI_SOURCE_DIR" ]; then
    echo "Copying SNI files from $SNI_SOURCE_DIR to $CLIENT_TMP_DIR/opt/fptn/SNI"
    cp -r "$SNI_SOURCE_DIR"/* "$CLIENT_TMP_DIR/opt/fptn/SNI/"
else
    echo "Warning: SNI source directory not found: $SNI_SOURCE_DIR"
fi

# copy qt
QT_LIBS_DIR=$CLIENT_TMP_DIR/opt/fptn/qt6/
QT_PLUGINS_DIR="$QT_LIBS_DIR/plugins"
mkdir -p "$QT_LIBS_DIR"
mkdir -p "$QT_PLUGINS_DIR"

find ~/.conan2 -path "*/Release/qtbase/lib/libQt6*.so*" -print0 | xargs -0 cp -av -t "$QT_LIBS_DIR"
find ~/.conan2 -type d -path "*/Release/qtbase/plugins" | grep -E "/qt[0-9a-f]+" | while read -r dir; do
    cp -rv "$dir"/* "$QT_PLUGINS_DIR"
done

# Create wrapper script
cat <<EOL > "$CLIENT_TMP_DIR/usr/bin/fptn-client"
#!/usr/bin/env bash

export FPTN_QT_DIR="/opt/fptn/qt6"
export QT_PLUGIN_PATH="\$FPTN_QT_DIR/plugins"
export QT_QPA_PLATFORM_PLUGIN_PATH="\$FPTN_QT_DIR/plugins/platforms"
export LD_LIBRARY_PATH="\$FPTN_QT_DIR:\$QT_QPA_PLATFORM_PLUGIN_PATH"

cleanup_dns() {
    echo "Cleaning up DNS settings..."
    resolvectl revert tun0
}

notify_error() {
    local message="\$1"
    notify-send -u critical "Error in Script" "\$message" || echo "D'oh"
}

declare -a VARS
VARS+=(
    "QT_PLUGIN_PATH=\$QT_PLUGIN_PATH"
    "QT_QPA_PLATFORM_PLUGIN_PATH=\$QT_QPA_PLATFORM_PLUGIN_PATH"
    "LD_LIBRARY_PATH=\$LD_LIBRARY_PATH"
)
for VAR in \$(env | sed 's/=/\t/g' | awk '{ print \$1 }' | tr '\n' ' '); do
    if [[ ! " \${VARS[@]} " =~ " \$VAR=" ]]; then
        VARS+=("\$VAR=\${!VAR}")
    fi
done

PROCESS_NAME="fptn-client-gui"
PID=\$(pgrep "\$PROCESS_NAME")
if [ -n "\$PID" ]; then
    cleanup_dns || echo "Failed to clean dns"

    echo "Process \$PROCESS_NAME found with PID \$PID. Attempting to kill it."
    kill "\$PID" || echo "Failed to stop"
    sleep 5

    PID=\$(pgrep "\$PROCESS_NAME")
    if [ -n "\$PID" ]; then
        echo "Process \$PROCESS_NAME still running. Force killing it."
        pkill -9 "\$PROCESS_NAME" || echo "Failed to kill"
    else
        echo "Process \$PROCESS_NAME successfully terminated."
    fi
else
    echo "Process \$PROCESS_NAME not found."
fi

TUN_INTERFACE=\$(ip link show | grep -o 'tun0')
if [ -n "\$TUN_INTERFACE" ]; then
    notify_error "TUN interface \$TUN_INTERFACE found. Disabling another VPN."
else
    echo "No TUN interface found."
fi

chattr -i /etc/resolv.conf
trap cleanup_dns EXIT
exec pkexec env -u PKEXEC_UID "SUDO_USER=\$USER" "SUDO_UID=\$(id -u)" "SUDO_GID=\$(id -g)" "\${VARS[@]}" "/bin/sh" -c "/opt/fptn/fptn-client-gui \"\$@\"; [ -x /usr/sbin/fptn-resolv-heal ] && /usr/sbin/fptn-resolv-heal" "\$@"

EOL
chmod 755 "$CLIENT_TMP_DIR/usr/bin/fptn-client"

# Create .desktop file
cp "$CLIENT_ICON" "$CLIENT_TMP_DIR/usr/share/icons/hicolor/512x512/apps/fptn-client.png"
cat <<EOL > "$CLIENT_TMP_DIR/usr/share/applications/fptn-client.desktop"
[Desktop Entry]
Name=FPTN Client
Comment=FPTN VPN Client
Exec=/usr/bin/fptn-client
Icon=/usr/share/icons/hicolor/512x512/apps/fptn-client.png
Terminal=false
Type=Application
Categories=Network;Utility;
EOL

# Create control file for client package
INSTALLED_SIZE=$(du -s "$CLIENT_TMP_DIR/usr" | cut -f1)
cat <<EOL > "$CLIENT_TMP_DIR/DEBIAN/control"
Package: fptn-client
Version: ${VERSION}
Architecture: $(dpkg --print-architecture)
Maintainer: ${MAINTAINER}
Installed-Size: ${INSTALLED_SIZE}
Depends: iptables, iproute2, net-tools, libgl1, libx11-6, libx11-xcb1, libfontenc1, libxcb-cursor0
Provides: fptn-client
Replaces: fptn-client
Conflicts: fptn-client
Section: admin
Priority: optional
Description: fptn client
EOL

# Create postinst file
cat <<EOL > "$CLIENT_TMP_DIR/DEBIAN/postinst"
#!/bin/bash

update-desktop-database || true

# Boot-time healer: restores /etc/resolv.conf on the next boot if a VPN
# session was interrupted (shutdown/crash) and left the VPN DNS locked in.
# Generated here (not shipped) so the GUI and CLI packages can coexist.
cat > /usr/sbin/fptn-resolv-heal <<'HEAL'
#!/bin/sh
[ -e /etc/resolv.conf.fptn-backup ] || exit 0
chattr -i /etc/resolv.conf 2>/dev/null || true
cp -f /etc/resolv.conf.fptn-backup /etc/resolv.conf
rm -f /etc/resolv.conf.fptn-backup
HEAL
chmod 755 /usr/sbin/fptn-resolv-heal

cat > /lib/systemd/system/fptn-resolv-heal.service <<'UNIT'
[Unit]
Description=FPTN: restore /etc/resolv.conf after an interrupted VPN session
DefaultDependencies=no
Before=network-pre.target systemd-resolved.service NetworkManager.service
Wants=network-pre.target
ConditionPathExists=/etc/resolv.conf.fptn-backup

[Service]
Type=oneshot
ExecStart=/usr/sbin/fptn-resolv-heal

[Install]
WantedBy=sysinit.target
UNIT

systemctl daemon-reload || true
systemctl enable fptn-resolv-heal.service || true
EOL
chmod 755 "$CLIENT_TMP_DIR/DEBIAN/postinst"

# Create prerm file
cat <<EOL > "$CLIENT_TMP_DIR/DEBIAN/prerm"
#!/bin/bash

PROCESS_NAME="fptn-client-gui"
PID=\$(pgrep "\$PROCESS_NAME")
if [ -n "\$PID" ]; then
    echo "Process \$PROCESS_NAME found with PID \$PID. Attempting to kill it."
    kill "\$PID" || echo "Failed to stop process \$PROCESS_NAME"
    sleep 5

    PID=\$(pgrep "\$PROCESS_NAME")
    if [ -n "\$PID" ]; then
        echo "Process \$PROCESS_NAME still running. Force killing it."
        pkill -9 "\$PROCESS_NAME" || echo "Failed to force kill process \$PROCESS_NAME"
    else
        echo "Process \$PROCESS_NAME successfully terminated."
    fi
else
    echo "Process \$PROCESS_NAME not found."
fi
EOL
chmod 755 "$CLIENT_TMP_DIR/DEBIAN/prerm"

# Create postrm file
cat <<EOL > "$CLIENT_TMP_DIR/DEBIAN/postrm"
#!/bin/bash

if [ "\$1" != "upgrade" ]; then
    rm -rf "/opt/fptn" || true
    rm -f "/usr/bin/fptn-client" || true
    rm -f "/usr/share/icons/hicolor/512x512/apps/fptn-client.png" || true
    rm -f "/usr/share/applications/fptn-client.desktop" || true
    # Drop the shared resolv healer only if the CLI package is gone too
    if ! dpkg -s fptn-client-cli >/dev/null 2>&1; then
        systemctl disable fptn-resolv-heal.service 2>/dev/null || true
        rm -f /lib/systemd/system/fptn-resolv-heal.service 2>/dev/null || true
        rm -f /usr/sbin/fptn-resolv-heal 2>/dev/null || true
        systemctl daemon-reload 2>/dev/null || true
    fi
fi
update-desktop-database || true
EOL
chmod 755 "$CLIENT_TMP_DIR/DEBIAN/postrm"

# Build the Debian package
dpkg-deb --root-owner-group --build "$CLIENT_TMP_DIR" "fptn-client-${VERSION}-${OS_NAME}${OS_VERSION}-$(dpkg --print-architecture).deb"

# Clean up temporary directories
rm -rf "$CLIENT_TMP_DIR"

echo "Client Debian package created successfully."

#!/bin/bash

set -e

# Function to show error messages
show_error() {
    local message="$1"
    osascript <<EOF
display dialog "$message" buttons {"OK"} default button "OK" with icon stop
EOF
    exit 1
}

# Function to show informational messages
show_info() {
    local message="$1"
    osascript <<EOF
display dialog "$message" buttons {"OK"} default button "OK" with icon note
EOF
}

SYMLINK_DIR="/usr/local/bin"
SYMLINK_PATH="$SYMLINK_DIR/fptn-client-cli"
APP_EXECUTABLE="/Applications/FptnClient.app/Contents/MacOS/fptn-client-cli-wrapper.sh"

# Create directory if it doesn't exist
if [ ! -d "$SYMLINK_DIR" ]; then
    if mkdir -p "$SYMLINK_DIR"; then
        echo "Created directory: $SYMLINK_DIR"
    else
        show_error "Failed to create required directory: $SYMLINK_DIR"
    fi
fi

# Handle existing symlink
if [ -L "$SYMLINK_PATH" ]; then
    echo "Found existing symlink at $SYMLINK_PATH - replacing it..."
    if ! rm -f "$SYMLINK_PATH"; then
        show_error "Failed to remove existing symlink at $SYMLINK_PATH"
    fi
fi

# Create new symlink
if ln -s "$APP_EXECUTABLE" "$SYMLINK_PATH"; then
    echo "Created symlink: $SYMLINK_PATH → $APP_EXECUTABLE"
else
    show_error "Failed to create symlink at $SYMLINK_PATH\n\nPlease check if you have sufficient permissions."
fi

# Install the boot-time DNS reset. If a VPN session was interrupted
# (crash / kill / power loss) and left the VPN DNS in place, this resets
# every network service back to DHCP DNS on the next system start.
SUPPORT_DIR="/Library/Application Support/FptnClient"
HEAL_SCRIPT="$SUPPORT_DIR/fptn-resolv-heal.sh"
HEAL_PLIST="/Library/LaunchDaemons/com.fptn.resolv-heal.plist"

mkdir -p "$SUPPORT_DIR"

cat > "$HEAL_SCRIPT" <<'HEAL'
#!/bin/bash
# Wait for SystemConfiguration (configd) to be ready — at early boot
# networksetup may not respond yet.
for i in $(seq 1 30); do
    networksetup -listallnetworkservices >/dev/null 2>&1 && break
    sleep 1
done
networksetup -listallnetworkservices | grep -v '^An asterisk' | \
    xargs -I {} networksetup -setdnsservers "{}" empty
HEAL
chmod 755 "$HEAL_SCRIPT"

cat > "$HEAL_PLIST" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.fptn.resolv-heal</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>/Library/Application Support/FptnClient/fptn-resolv-heal.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
PLIST
chmod 644 "$HEAL_PLIST"

launchctl unload "$HEAL_PLIST" 2>/dev/null || true
launchctl load -w "$HEAL_PLIST" 2>/dev/null || true

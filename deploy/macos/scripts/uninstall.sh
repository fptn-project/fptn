#!/bin/bash

SYMLINK_PATH="/usr/local/bin/fptn-client-cli"
if [ -L "$SYMLINK_PATH" ]; then
    echo "Deleting symbolic link..."
    sudo rm -f "$SYMLINK_PATH"
else
    echo "Symbolic link not found: $SYMLINK_PATH"
fi

HEAL_PLIST="/Library/LaunchDaemons/com.fptn.resolv-heal.plist"
if [ -f "$HEAL_PLIST" ]; then
    echo "Removing DNS self-heal daemon..."
    sudo launchctl unload "$HEAL_PLIST" 2>/dev/null || true
    sudo rm -f "$HEAL_PLIST"
fi
sudo rm -rf "/Library/Application Support/FptnClient"

echo "tun.kext and related files have been removed."

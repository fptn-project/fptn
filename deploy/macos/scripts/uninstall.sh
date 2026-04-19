#!/bin/bash

SYMLINK_PATH="/usr/local/bin/fptn-client-cli"
if [ -L "$SYMLINK_PATH" ]; then
    echo "Deleting symbolic link..."
    sudo rm -f "$SYMLINK_PATH"
else
    echo "Symbolic link not found: $SYMLINK_PATH"
fi

echo "tun.kext and related files have been removed."

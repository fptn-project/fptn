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

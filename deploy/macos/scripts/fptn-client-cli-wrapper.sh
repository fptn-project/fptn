#!/bin/bash

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "This operation requires root privileges."
    exit 1
fi


# Function to clean DNS settings
cleanup_dns() {
    echo "Cleaning up DNS settings..."
    networksetup -listallnetworkservices | grep -v '^An asterisk' | xargs -I {} networksetup -setdnsservers "{}" empty
}

cd /tmp/

networksetup -listallnetworkservices | grep -v '^An asterisk' | xargs -I {} networksetup -setdnsservers "{}" empty

trap cleanup_dns EXIT
/Applications/FptnClient.app/Contents/MacOS/fptn-client-cli "$@"

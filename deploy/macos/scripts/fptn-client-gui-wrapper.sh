#!/bin/bash

# Dialog display functions
show_error() {
    osascript -e "display dialog \"$1\" buttons {\"OK\"} default button \"OK\" with icon stop"
    exit 1
}

is_client_running() {
    pgrep -f "fptn-client-gui" > /dev/null
}

show_dialog() {
    local message="$1"
    local buttons="$2"
    local default_button="$3"
    local icon="$4"

    osascript -e "display dialog \"$message\" buttons {$buttons} default button \"$default_button\" with icon $icon"
}

copy_sni_files() {
    local SNI_SRC="/Applications/FptnClient.app/Contents/Resources/SNI"
    local USER_HOME="$HOME"
    local SNI_USER_DIR="$USER_HOME/Library/Preferences/SNI"

    # Check if SNI directory exists and has all files
    local need_copy=false

    if [ ! -d "$SNI_USER_DIR" ]; then
        echo "SNI directory doesn't exist, need to copy files"
        need_copy=true
    else
        # Check if any SNI files are missing in user directory
        for file in "$SNI_SRC"/*; do
            if [ -f "$file" ]; then
                filename=$(basename "$file")
                user_file="$SNI_USER_DIR/$filename"
                if [ ! -f "$user_file" ]; then
                    echo "File $filename missing in user directory, need to copy"
                    need_copy=true
                    break
                fi
            fi
        done
    fi

    # Copy files if needed
    if [ "$need_copy" = true ] && [ -d "$SNI_SRC" ]; then
        echo "Copying SNI files to user directory..."
        mkdir -p "$SNI_USER_DIR"
        cp -R "$SNI_SRC/"* "$SNI_USER_DIR/"
        echo "SNI files copied successfully to $SNI_USER_DIR"
    elif [ ! -d "$SNI_SRC" ]; then
        echo "Warning: SNI source folder not found: $SNI_SRC"
    else
        echo "SNI files are already up to date"
    fi
}

# Reset DNS settings
clean_dns() {
    networksetup -listallnetworkservices | grep -v '^An asterisk' | \
    xargs -I {} networksetup -setdnsservers "{}" empty
}

copy_sni_files

# Set environment and launch application
export QT_PLUGIN_PATH=/Applications/FptnClient.app/Contents/Frameworks/plugins
export QT_QPA_PLATFORM_PLUGIN_PATH=$QT_PLUGIN_PATH/platforms
export LD_LIBRARY_PATH=/Applications/FptnClient.app/Contents/Frameworks

clean_dns

# run in background
/Applications/FptnClient.app/Contents/MacOS/fptn-client-gui "$@" &

# wait for end of client
while is_client_running; do
    sleep 1
done

clean_dns

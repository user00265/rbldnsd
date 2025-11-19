#!/bin/sh
# rbldnsd Docker entrypoint script
# Allows flexible configuration handling

set -e

# Default config path
CONFIG_PATH="${CONFIG_PATH:-/config/rbldnsd.yaml}"

# If no arguments provided, use config file
if [ $# -eq 0 ]; then
    # Check if config file exists
    if [ ! -f "$CONFIG_PATH" ]; then
        echo "Error: Config file not found at $CONFIG_PATH"
        echo "Set CONFIG_PATH environment variable to override"
        echo "Or pass rbldnsd flags as arguments"
        exit 1
    fi
    set -- -c "$CONFIG_PATH"
fi

# Execute rbldnsd with arguments (or config file)
exec /usr/local/bin/rbldnsd "$@"

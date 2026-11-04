#!/bin/sh
# Stop only on removal, not while upgrading. Debian passes "remove", and RPM passes 0 for removal.
if [ "$1" = "remove" ] || [ "$1" = "0" ]; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now ferrixdns || true
    fi
fi

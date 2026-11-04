#!/bin/sh
# Enabling the service is left to the operator, because it changes how this machine answers DNS.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
echo "FerrixDNS is installed. Review /etc/ferrixdns/ferrixdns.env, then run:"
echo "  systemctl enable --now ferrixdns"
echo "  journalctl -u ferrixdns | grep setup_token"

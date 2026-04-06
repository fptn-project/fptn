#!/bin/bash

export OUT_NETWORK_INTERFACE=$(ip -o -4 route show to default | awk '{print $5}')
echo "[FPTN] Using network interface: $OUT_NETWORK_INTERFACE"

exec /usr/local/bin/fptn-server \
    --server-key=/etc/fptn/server.key \
    --server-crt=/etc/fptn/server.crt \
    --out-network-interface="${OUT_NETWORK_INTERFACE}" \
    --server-port=443 \
    --enable-detect-probing="${ENABLE_DETECT_PROBING}" \
    --default-proxy-domain="${DEFAULT_PROXY_DOMAIN}" \
    --allowed-sni-list="${ALLOWED_SNI_LIST}" \
    --tun-interface-name=fptn0 \
    --disable-bittorrent="$DISABLE_BITTORRENT" \
    --prometheus-access-key="$PROMETHEUS_SECRET_ACCESS_KEY" \
    --use-remote-server-auth="$USE_REMOTE_SERVER_AUTH" \
    --remote-server-auth-host="$REMOTE_SERVER_AUTH_HOST" \
    --remote-server-auth-port="$REMOTE_SERVER_AUTH_PORT" \
    --max-active-sessions-per-user="$MAX_ACTIVE_SESSIONS_PER_USER" \
    --server-external-ips="${SERVER_EXTERNAL_IPS}" \
    --client-dns-server-ipv4="${CLIENT_DNS_SERVER_IPV4}" \
    --client-dns-server-ipv6="${CLIENT_DNS_SERVER_IPV6}"


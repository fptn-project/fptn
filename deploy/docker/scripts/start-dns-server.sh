#!/bin/bash


start_unbound() {
    echo "Starting unbound..."

    DO_IP6="no"
    [ "${DNS_IPV6_ENABLE:-false}" = "true" ] && DO_IP6="yes"

    CONFIG_FILE="/etc/unbound/unbound.conf"
    ROOT_HINTS="/etc/unbound/root.hints"
    echo "Using DNS settings:"
    echo "  IPv4: yes"
    echo "  IPv6: $DO_IP6"

    if [ "${DNS_IPV6_ENABLE:-false}" = "true" ]; then
        cat > "$CONFIG_FILE" << EOF
server:
    interface: 0.0.0.0
    interface: ::0
    port: 53
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes

    access-control: 0.0.0.0/0 allow
    access-control: ::0/0 allow

    root-hints: "/etc/unbound/root.hints"

    cache-max-ttl: 86400
    cache-min-ttl: 3600

    hide-identity: yes
    hide-version: yes

forward-zone:
    name: "."
    forward-addr: ${DNS_IPV4_PRIMARY:-8.8.8.8}
    forward-addr: ${DNS_IPV4_SECONDARY:-8.8.4.4}
    forward-addr: 1.1.1.1
    forward-addr: 1.0.0.1
    forward-addr: 9.9.9.9
    forward-addr: ${DNS_IPV6_PRIMARY:-2001:4860:4860::8888}
    forward-addr: ${DNS_IPV6_SECONDARY:-2001:4860:4860::8844}
EOF
    else
        cat > "$CONFIG_FILE" << EOF
server:
    interface: 0.0.0.0
    port: 53
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes

    access-control: 0.0.0.0/0 allow

    root-hints: "/etc/unbound/root.hints"

    cache-max-ttl: 86400
    cache-min-ttl: 3600

    hide-identity: yes
    hide-version: yes
    prefer-ip4: yes
    prefer-ip6: no

    private-address: ::/0
    do-not-query-localhost: no
    unwanted-reply-threshold: 0

forward-zone:
    name: "."
    forward-addr: ${DNS_IPV4_PRIMARY:-8.8.8.8}
    forward-addr: ${DNS_IPV4_SECONDARY:-8.8.4.4}
    forward-addr: 1.1.1.1
    forward-addr: 1.0.0.1
    forward-addr: 9.9.9.9
EOF
    fi

    if wget -4 -q --timeout=10 --tries=2 -O "$ROOT_HINTS.tmp" https://www.internic.net/domain/named.root; then
        mv "$ROOT_HINTS.tmp" "$ROOT_HINTS"
    else
        rm -f "$ROOT_HINTS.tmp"
        [ -f "$ROOT_HINTS" ] || cp /usr/share/dns/root.hints "$ROOT_HINTS"
    fi
    exec unbound -d -c "$CONFIG_FILE"
}

start_dnsmasq() {
    echo "Starting dnsmasq..."

    CONFIG_FILE="/etc/dnsmasq.conf"
    DNS_IPV6_ENABLE="${DNS_IPV6_ENABLE:-false}"

    rm -f "$CONFIG_FILE"

    if [ "$DNS_IPV6_ENABLE" = "true" ]; then
        if [ -n "$DNS_IPV4_PRIMARY" ]; then
            echo "server=$DNS_IPV4_PRIMARY" >> "$CONFIG_FILE"
        fi
        if [ -n "$DNS_IPV4_SECONDARY" ]; then
            echo "server=$DNS_IPV4_SECONDARY" >> "$CONFIG_FILE"
        fi
        if [ -n "$DNS_IPV6_PRIMARY" ]; then
            echo "server=$DNS_IPV6_PRIMARY" >> "$CONFIG_FILE"
        fi
        if [ -n "$DNS_IPV6_SECONDARY" ]; then
            echo "server=$DNS_IPV6_SECONDARY" >> "$CONFIG_FILE"
        fi
        if [ ! -s "$CONFIG_FILE" ]; then
            echo "server=8.8.8.8" >> "$CONFIG_FILE"
            echo "server=8.8.4.4" >> "$CONFIG_FILE"
            echo "server=2001:4860:4860::8888" >> "$CONFIG_FILE"
            echo "server=2001:4860:4860::8844" >> "$CONFIG_FILE"
        fi
    else
        if [ -n "$DNS_IPV4_PRIMARY" ]; then
            echo "server=$DNS_IPV4_PRIMARY" >> "$CONFIG_FILE"
        fi
        if [ -n "$DNS_IPV4_SECONDARY" ]; then
            echo "server=$DNS_IPV4_SECONDARY" >> "$CONFIG_FILE"
        fi
        if [ ! -s "$CONFIG_FILE" ]; then
            echo "server=8.8.8.8" >> "$CONFIG_FILE"
            echo "server=8.8.4.4" >> "$CONFIG_FILE"
        fi
        echo "filter-AAAA" >> "$CONFIG_FILE"
    fi

    cat >> "$CONFIG_FILE" << EOF
dns-forward-max=512
cache-size=16384
local-ttl=14400
neg-ttl=120
no-resolv
no-poll
EOF

    echo "Using DNS servers:"
    echo "  IPv4: ENABLED"
    echo "    Primary:   ${DNS_IPV4_PRIMARY:-8.8.8.8 (default)}"
    echo "    Secondary: ${DNS_IPV4_SECONDARY:-8.8.4.4 (default)}"

    if [ "$DNS_IPV6_ENABLE" = "true" ]; then
        echo "  IPv6: ENABLED"
        echo "    Primary:   ${DNS_IPV6_PRIMARY:-2001:4860:4860::8888 (default)}"
        echo "    Secondary: ${DNS_IPV6_SECONDARY:-2001:4860:4860::8844 (default)}"
    else
        echo "  IPv6: DISABLED"
    fi

    exec /usr/sbin/dnsmasq --no-daemon
}


case "$USING_DNS_SERVER" in
    "unbound")
        start_unbound
        ;;
    "dnsmasq")
        start_dnsmasq
        ;;
    *)
        echo "Unknown USING_DNS_SERVER: $USING_DNS_SERVER, using dnsmasq"
        start_dnsmasq
        ;;
esac
exit 0

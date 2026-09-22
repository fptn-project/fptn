#!/bin/sh
# Argument parsing, before any connection. Pass = reached the server choice or
# a clear config error; fail = the parser gave up (usage/Unknown/Duplicate).
BIN=/tmp/fc
DIR=/tmp/fcases
mkdir -p $DIR
pass=0; fail=0

run() {
  name="$1"; shift
  out=$($BIN "$@" 2>&1 | head -40)
  if echo "$out" | grep -qE "Unknown argument|Duplicate argument|Zero positional|Usage: fptn-client"; then
    echo "FAIL    $name"
    echo "$out" | grep -E "Unknown|Duplicate|Zero positional" | head -1 | sed 's/^/          /'
    fail=$((fail+1))
  else
    echo "ok      $name"
    pass=$((pass+1))
  fi
}

# --- configs ---
cat > $DIR/base.json <<J
{"socks_listen":"127.0.0.9:20991","tun_interface_name":"zbt0","disable_routing":true,
 "tun_interface_ip":"192.0.2.9","access_token":["TOKEN"]}
J
cat > $DIR/dashes.json <<J
{"socks-listen":"127.0.0.9:20992","tun-interface-name":"zbt0","disable-routing":"true",
 "tun-interface-ip":"192.0.2.9","access-token":["TOKEN"]}
J
cat > $DIR/boolfalse.json <<J
{"socks_listen":"127.0.0.9:20993","disable_routing":false,"access_token":["TOKEN"]}
J
cat > $DIR/nulls.json <<J
{"socks_listen":"127.0.0.9:20994","preferred_server":null,"max_ping":null,"access_token":["TOKEN"]}
J
cat > $DIR/numbers.json <<J
{"socks_listen":"127.0.0.9:20995","socks_route_table":1099,"mtu_size":1400,"max_ping":900,
 "disable_routing":true,"access_token":["TOKEN"]}
J
cat > $DIR/twotokens.json <<J
{"socks_listen":"127.0.0.9:20996","disable_routing":true,"access_token":["TOKEN","TOKEN"]}
J
cat > $DIR/allflags.json <<J
{"socks_listen":"127.0.0.9:20997","socks_route_table":1098,"disable_routing":true,
 "routing_mark":"0x40000000","tun_interface_name":"zbt0","tun_interface_ip":"192.0.2.9",
 "tun_interface_ipv6":"fd00:5a42:9::1","mtu_size":1400,"sni":"google.com",
 "bypass_method":"obfuscation","connection_strategy":"rolling-tunnel",
 "exclude_tunnel_networks":"10.0.0.0/8,192.168.0.0/16","include_tunnel_networks":"",
 "enable_split_tunnel":false,"split_tunnel_mode":"exclude","split_tunnel_domains":"ru,su",
 "blacklist_domains":"ria.ru","exclude_servers":"Russia|Vietnam",
 "max_ping":900,"preferred_server":"","out_network_interface":"",
 "access_token":["TOKEN"]}
J
cat > $DIR/badjson.json <<J
{ thisisnotjson
J
cat > $DIR/notobject.json <<J
["an array, not an object"]
J

for f in $DIR/*.json; do sed -i "s|TOKEN|$1|g" "$f"; done

run "config with underscores"          -c $DIR/base.json
run "config with dashes"               -c $DIR/dashes.json
run "disable_routing=false"            -c $DIR/boolfalse.json
run "null values are skipped"          -c $DIR/nulls.json
run "numeric values"                   -c $DIR/numbers.json
run "two tokens in an array"           -c $DIR/twotokens.json
run "every flag at once"               -c $DIR/allflags.json
run "override: port from cmdline"      --socks-listen 127.0.0.9:20981 -c $DIR/base.json
run "override with an underscore"      --socks_listen 127.0.0.9:20982 -c $DIR/base.json
run "token override from cmdline"      --access-token "$1" -c $DIR/base.json
run "long form --config"               --config $DIR/base.json
run "flags only, no config"            --socks-listen 127.0.0.9:20983 --disable-routing --access-token "$1"

echo "--- expected errors (not a parse failure) ---"
for t in "broken JSON:$DIR/badjson.json" "not an object:$DIR/notobject.json" "missing file:/tmp/fcases/missing.json"; do
  n=${t%%:*}; f=${t#*:}
  out=$($BIN -c "$f" 2>&1 | head -5)
  if echo "$out" | grep -qE "Cannot open config file|must contain a JSON object|parse error|Config file"; then
    echo "ok      $n - clear error"; pass=$((pass+1))
  else
    echo "FAIL    $n"; echo "$out" | head -2 | sed 's/^/          /'; fail=$((fail+1))
  fi
done

out=$($BIN --help 2>&1 | head -3); echo "$out" | grep -q "Usage: fptn-client" && { echo "ok      --help"; pass=$((pass+1)); } || { echo "FAIL    --help"; fail=$((fail+1)); }
out=$($BIN --version 2>&1 | tail -1); echo "$out" | grep -qE "^[0-9]+\.[0-9]+" && { echo "ok      --version ($out)"; pass=$((pass+1)); } || { echo "FAIL    --version"; fail=$((fail+1)); }

echo
echo "TOTAL: passed $pass, failed $fail"

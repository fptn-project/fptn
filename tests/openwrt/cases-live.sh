#!/bin/sh
# Live checks: the client really brings the tunnel up and moves traffic through
# SOCKS. Router routes are left alone (--disable-routing), the port is its own.
BIN=/tmp/fc
TOK="$1"
DIR=/tmp/fcases
mkdir -p $DIR
pass=0; fail=0

start() {          # start <config-file> <seconds to wait>
  $BIN -c "$1" > /tmp/live.log 2>&1 &
  PID=$!
  i=0
  while [ $i -lt "$2" ]; do
    grep -q "SOCKS5 proxy listening" /tmp/live.log && return 0
    grep -qE "Config error|All servers unavailable|No servers left" /tmp/live.log && return 1
    sleep 2; i=$((i+2))
  done
  return 1
}
stop() { kill $PID 2>/dev/null; sleep 2; kill -9 $PID 2>/dev/null; }

check() {          # check <name> <success condition 0/1>
  if [ "$2" -eq 0 ]; then echo "ok      $1"; pass=$((pass+1));
  else echo "FAIL    $1"; fail=$((fail+1)); fi
}

mk() {             # mk <file> <extra fields>
  cat > "$1" <<J
{"socks_listen":"127.0.0.9:20990","disable_routing":true,"tun_interface_name":"zbt0",
 "tun_interface_ip":"192.0.2.9","tun_interface_ipv6":"fd00:5a42:9::1",
 "bypass_method":"obfuscation","routing_mark":"0x40000000"$2,
 "access_token":["$TOK"]}
J
}

echo "=== 1. basic connection and traffic through SOCKS ==="
mk $DIR/live.json ""
if start $DIR/live.json 90; then
  check "tunnel is up" 0
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 25 --socks5 127.0.0.9:20990 https://api.ipify.org)
  [ "$code" = "200" ] && check "TCP through SOCKS (curl 200)" 0 || { check "TCP through SOCKS (code $code)" 1; }
  ip=$(curl -s --max-time 25 --socks5 127.0.0.9:20990 https://api.ipify.org)
  echo "        external IP through the tunnel: $ip"
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 25 --socks5-hostname 127.0.0.9:20990 https://api.ipify.org)
  [ "$code" = "200" ] && check "name resolves inside the tunnel" 0 || check "name resolves inside the tunnel (code $code)" 1
  echo "        client descriptors: $(ls /proc/$PID/fd 2>/dev/null | wc -l), RSS: $(awk '/VmRSS/{print $2}' /proc/$PID/status 2>/dev/null)kB"
else
  check "tunnel is up" 1; tail -3 /tmp/live.log | sed 's/^/        /'
fi
stop

echo "=== 2. preferred_server by name ==="
mk $DIR/pref.json ',"preferred_server":"Server-1"'
if start $DIR/pref.json 60; then
  grep -q "SELECTED SERVER" /tmp/live.log && echo "        $(grep -m1 'SELECTED SERVER' /tmp/live.log | sed 's/.*SELECTED SERVER: *//')"
  check "preferred_server accepted" 0
else check "preferred_server accepted" 1; tail -2 /tmp/live.log | sed 's/^/        /'; fi
stop

echo "=== 3. exclude_servers drops everything by regex ==="
mk $DIR/excl.json ',"exclude_servers":".*"'
$BIN -c $DIR/excl.json > /tmp/live.log 2>&1 &
PID=$!; sleep 12; stop
grep -q "No servers left" /tmp/live.log && check "empty pool - clear error" 0 || { check "empty pool" 1; tail -2 /tmp/live.log | sed 's/^/        /'; }

echo "=== 4. unreachable max_ping ==="
mk $DIR/ping.json ',"max_ping":1'
$BIN -c $DIR/ping.json > /tmp/live.log 2>&1 &
PID=$!; sleep 60; stop
grep -qE "over the 1 ms limit|did not answer the latency check" /tmp/live.log && check "max_ping takes effect" 0 || { check "max_ping takes effect" 1; tail -2 /tmp/live.log | sed 's/^/        /'; }

echo "=== 5. unknown bypass_method ==="
mk $DIR/bad.json ',"bypass_method":"no-such-method"'
$BIN -c $DIR/bad.json > /tmp/live.log 2>&1 &
PID=$!; sleep 10; stop
grep -qiE "bypass|method|Unknown|error" /tmp/live.log && check "clear reaction to a bad bypass_method" 0 || { check "bad bypass_method" 1; tail -2 /tmp/live.log | sed 's/^/        /'; }

echo
echo "TOTAL: passed $pass, failed $fail"

#!/bin/sh
# shellcheck disable=SC2016,SC2034,SC2317,SC2329
# Test of /usr/sbin/parker-ra-goodbye with mock commands (ip, ip6tables,
# uradvd, logger). It does not need a Gluon node.
# Run: sh tests/ra-goodbye-test.sh (from the package directory, busybox sh
# or bash, needs /proc), for example:
#   docker run --rm -v "$PWD":/w -w /w alpine:3.20 sh tests/ra-goodbye-test.sh

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT=$HERE/../files/usr/sbin/parker-ra-goodbye
OWN=fe80::1
NEW=fe80::2

SIM=$(mktemp -d)
cleanup() { rm -rf "$SIM"; }
trap cleanup EXIT
mkdir "$SIM/bin"
export SIM PID_FILE="$SIM/pid" URADVD="$SIM/bin/uradvd" RA_STATE="$SIM/ra-state"

cat > "$SIM/bin/ip" <<'EOF'
#!/bin/sh
case "$*" in
"-6 addr show dev br-client scope link")
	printf '5: br-client: <UP>\n    inet6 fe80::1/64 scope link\n' ;;
"-6 addr show dev br-client scope global")
	cat "$SIM/addr" 2>/dev/null ;;
"-6 route show default dev br-client")
	cat "$SIM/route" 2>/dev/null ;;
esac
EOF
cat > "$SIM/bin/ip6tables" <<'EOF'
#!/bin/sh
echo "$*" >> "$SIM/ipt"
EOF
cat > "$SIM/bin/uradvd" <<'EOF'
#!/bin/sh
echo "$*" >> "$SIM/uradvd"
echo $$ > "$SIM/uradvd.pid"
exec sleep 1000
EOF
cat > "$SIM/bin/logger" <<'EOF'
#!/bin/sh
echo "$*" >> "$SIM/log"
EOF
chmod +x "$SIM/bin/"*
PATH=$SIM/bin:$PATH

FAIL=0
check() {
	if eval "$2"; then
		echo "PASS $1"
	else
		echo "FAIL $1"
		FAIL=1
	fi
}
reset() {
	rm -f "$SIM/route" "$SIM/ra-state" "$SIM/ipt" "$SIM/uradvd" "$SIM/uradvd.pid" "$SIM/log" "$PID_FILE"
	: > "$SIM/ipt"
	# A preferred address of the new router's prefix
	printf '    inet6 2001:db8:3::5/64 scope global dynamic noprefixroute\n' > "$SIM/addr"
}
alive() { [ -n "$1" ] && kill -0 "$1" 2>/dev/null; }

# 1. No new router: no router lifetime 0.
reset
sh "$SCRIPT" 3 2 600 2001:db8:1::/64
check "no new router: no uradvd" '[ ! -e "$SIM/uradvd" ]'
check "no new router: no ip6tables rule" '[ ! -s "$SIM/ipt" ]'
check "no new router: pid file removed" '[ ! -e "$PID_FILE" ]'

# 2. A default route through the node itself is not a new router.
reset
echo "default from 2001:db8:1::/64 via $OWN dev br-client proto static metric 512" > "$SIM/route"
sh "$SCRIPT" 2 2 600 2001:db8:1::/64
check "own router only: no uradvd" '[ ! -e "$SIM/uradvd" ]'

# 3. The new router comes after 2 s: then router lifetime 0.
reset
sh "$SCRIPT" 30 2 600 2001:db8:1::/64 2001:db8:2::/64 &
job=$!
sleep 2
check "before the new router: no uradvd" '[ ! -e "$SIM/uradvd" ]'
echo "default from 2001:db8:3::/64 via $NEW dev br-client proto static metric 512" > "$SIM/route"
wait "$job"
check "new router: router lifetime 0 for all prefixes" \
	'[ "$(cat "$SIM/uradvd")" = "-i br-client --default-lifetime 0 --preferred-lifetime 0 --valid-lifetime 600 --min-router-adv-interval 3 --max-router-adv-interval 4 -a 2001:db8:1::/64 -a 2001:db8:2::/64" ]'
check "new router: own RAs dropped while it sends, rule removed after" \
	'[ "$(cat "$SIM/ipt")" = "$(printf "%s\n%s" "-w -t mangle -I INPUT -i br-client -s $OWN -p ipv6-icmp --icmpv6-type router-advertisement -j DROP" "-w -t mangle -D INPUT -i br-client -s $OWN -p ipv6-icmp --icmpv6-type router-advertisement -j DROP")" ]'
check "new router: uradvd stopped after the duration" '! alive "$(cat "$SIM/uradvd.pid")"'
check "new router: pid file removed" '[ ! -e "$PID_FILE" ]'

# 4. Cancel while it waits: it stops at once, no router lifetime 0.
reset
sh "$SCRIPT" 30 2 600 2001:db8:1::/64 &
job=$!
sleep 1
check "pid file has the pid of the script" '[ "$(cat "$PID_FILE")" = "$job" ]'
kill "$job"
sleep 1
check "cancel while waiting: stopped at once" '! alive "$job"'
echo "default via $NEW dev br-client" > "$SIM/route"
sleep 3
check "cancel while waiting: no uradvd" '[ ! -e "$SIM/uradvd" ]'

# 5. Cancel while it sends: uradvd stops at once, the rule is removed.
reset
echo "default via $NEW dev br-client" > "$SIM/route"
sh "$SCRIPT" 30 60 600 2001:db8:1::/64 &
job=$!
sleep 3
upid=$(cat "$SIM/uradvd.pid" 2>/dev/null)
check "sending: uradvd runs" 'alive "$upid"'
kill "$job"
sleep 1
check "cancel while sending: script and uradvd stopped" '! alive "$job" && ! alive "$upid"'
check "cancel while sending: rule removed" '[ "$(grep -c -e " -D INPUT " "$SIM/ipt")" = 1 ]'

# 6. Multi-site: all sites of the node are down, then the new router comes.
reset
printf '2001:db8:1::/64,0,600\nrdnss 2001:db8:1::1\n' > "$SIM/ra-state"
echo "default via $NEW dev br-client" > "$SIM/route"
sh "$SCRIPT" 30 1 600 2001:db8:1::/64
check "multi-site, own sites down: router lifetime 0" '[ -e "$SIM/uradvd" ]'

# 7. Multi-site: a site of the node comes back before the grace time ends
# (all uplinks back at the same time): no router lifetime 0.
reset
printf '2001:db8:1::/64,0,600\n' > "$SIM/ra-state"
sh "$SCRIPT" 30 2 600 2001:db8:1::/64 &
job=$!
sleep 1
echo "default via $NEW dev br-client" > "$SIM/route"
printf '2001:db8:1::/64,180,600\n' > "$SIM/ra-state"
wait "$job"
check "multi-site, own site up again: no uradvd" '[ ! -e "$SIM/uradvd" ]'
check "multi-site, own site up again: log" 'grep -q "a site of this node is up again" "$SIM/log"'

# 8. A router with deprecated prefixes only (an uplink without tunnels) and
# deprecated own prefixes: not a new router, no router lifetime 0.
reset
printf '    inet6 2001:db8:3::5/64 scope global deprecated dynamic\n    inet6 2001:db8:1::5/64 scope global dynamic\n' > "$SIM/addr"
echo "default via $NEW dev br-client" > "$SIM/route"
sh "$SCRIPT" 2 1 600 2001:db8:1::/64
check "dead router (deprecated prefixes only): no uradvd" '[ ! -e "$SIM/uradvd" ]'
check "dead router: log no new router" 'grep -q "No new IPv6 router after 2s" "$SIM/log"'

exit "$FAIL"

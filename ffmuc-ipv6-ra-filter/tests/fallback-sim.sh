#!/bin/sh
# shellcheck disable=SC2016,SC2034,SC2317,SC2329
#
# Simulation of the fallback of ipv6-ra-filter. It does not need a Gluon node:
# small mock commands replace batctl, ebtables-tiny, ip6tables, ip, uci and
# ifup. A model of odhcp6c and netifd keeps the routers that the node knows:
# netifd installs only one IPv6 default route, the route of the router with
# the latest router advertisement (the route key of netifd has no gateway).
#
# Usage: sh tests/fallback-sim.sh [path to ipv6-ra-filter]

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT=${1:-$HERE/../files/lib/gluon/ffmuc-ipv6-ra-filter/ipv6-ra-filter}

O1=5e:dd:a8:05:04:6b
R1=52:54:00:aa:01:00
O2=3e:30:b1:77:ed:3b
R2=52:54:00:aa:06:00

FAIL=0
SIM=""

setup() {
	[ -n "$SIM" ] && rm -rf "$SIM"
	SIM=$(mktemp -d)
	export SIM
	mkdir "$SIM/bin"
	: > "$SIM/ebt"; : > "$SIM/ipt"; : > "$SIM/known"; : > "$SIM/alive"; : > "$SIM/log"
	: > "$SIM/drop"; : > "$SIM/uradvd"
	printf '%s 2001:db8:1::/64\n%s 2001:db8:2::/64\n' "$R1" "$R2" > "$SIM/prefix"
	echo 0 > "$SIM/ra_count"
	echo "0.00 0.00" > "$SIM/uptime"
	printf '* %s -1 [.......] ( 1) %s ( 1) (0x1)\n* %s -1 [.......] ( 1) %s ( 1) (0x2)\n' \
		"$R1" "$O1" "$R2" "$O2" > "$SIM/tg"
	sed -e "s#/proc/uptime#$SIM/uptime#" -e "s#/tmp/ffmuc#$SIM/ffmuc#g" -e "s#/var/lock/#$SIM/#" \
		-e "s#/var/run/#$SIM/#" -e "s#/usr/sbin/uradvd#$SIM/bin/uradvd#" \
		-e 's#(sleep "$1"; exec "$0") >/dev/null 2>&1 &#echo "$1" > "$SIM/timer"; return#' \
		"$SCRIPT" > "$SIM/filter"
	mocks
}

mocks() {
	cat > "$SIM/bin/logger" <<'EOF'
#!/bin/sh
shift 2; echo "$(cut -d. -f1 "$SIM/uptime") $*" >> "$SIM/log"
EOF
	cat > "$SIM/bin/lock" <<'EOF'
#!/bin/sh
exit 0
EOF
	cat > "$SIM/bin/batctl" <<'EOF'
#!/bin/sh
case "$1" in
gw_mode) echo client ;;
gwl) [ -s "$SIM/gw" ] && echo "* $(cat "$SIM/gw") ( 255) x [ primary0]: 10.0/2.0 MBit" ;;
tg) cat "$SIM/tg" ;;
esac
EOF
	cat > "$SIM/bin/uci" <<'EOF'
#!/bin/sh
case "$3" in
network.client6.proto) echo dhcpv6 ;;
network.client.proto) echo dhcp ;;
esac
EOF
	cat > "$SIM/bin/ebtables-tiny" <<'EOF'
#!/bin/sh
case "$1" in
-L) cat "$SIM/ebt" ;;
-F) : > "$SIM/ebt" ;;
-A) shift 2; echo "$*" >> "$SIM/ebt" ;;
-D) shift 2; grep -v -x -F -e "$*" "$SIM/ebt" > "$SIM/ebt.n"; mv "$SIM/ebt.n" "$SIM/ebt" ;;
esac
EOF
	cat > "$SIM/bin/ip6tables" <<'EOF'
#!/bin/sh
shift 3
case "$*" in
*DROP)
	rule="$*"; rule="${rule#* }"
	case "$1" in
	-C) grep -q -x -F -e "$rule" "$SIM/drop" ;;
	-I) echo "$rule" >> "$SIM/drop" ;;
	-D) grep -v -x -F -e "$rule" "$SIM/drop" > "$SIM/drop.n"; mv "$SIM/drop.n" "$SIM/drop" ;;
	esac
	exit ;;
esac
case "$1" in
-N|-C|-I) exit 0 ;;
-F) : > "$SIM/ipt"; echo 0 > "$SIM/ra_count" ;;
-A) echo "$6" >> "$SIM/ipt" ;;
-S) while read -r m; do echo "-A ffmuc_ra_count -m mac --mac-source $m -j RETURN"; done < "$SIM/ipt" ;;
-L) echo "$(cat "$SIM/ra_count") 0 RETURN all * * ::/0 ::/0 MAC x" ;;
esac
EOF
	cat > "$SIM/bin/ip" <<'EOF'
#!/bin/sh
case "$*" in
"-6 route show default dev br-client") [ -s "$SIM/known" ] &&
	echo "default via fe80::$(tail -n 1 "$SIM/known" | tr -d :) dev br-client proto static metric 512" ;;
"-6 route show dev br-client") for mac in $(cat "$SIM/known"); do
	awk -v m="$mac" '$1 == m { print $2 " proto static metric 256 pref medium" }' "$SIM/prefix"
done ;;
"-6 addr show dev br-client scope link") echo "    inet6 fe80::1/64 scope link" ;;
"-6 neigh show dev br-client to "*) echo "$7 lladdr $(echo "$7" | sed 's/fe80:://; s/\(..\)/\1:/g; s/:$//') router REACHABLE" ;;
esac
EOF
	cat > "$SIM/bin/ifup" <<'EOF'
#!/bin/sh
echo "$(cut -d. -f1 "$SIM/uptime") ifup $1" >> "$SIM/log"
[ "$1" = client6 ] || exit 0
# odhcp6c restarts: it forgets all routers and sends a router solicitation
: > "$SIM/known"
for mac in $(cat "$SIM/alive"); do "$SIM/bin/ra" "$mac"; done
EOF
	cat > "$SIM/bin/ra" <<'EOF'
#!/bin/sh
# A router advertisement from $1 arrives at the node
grep -q -x -e "-s $1 -j ACCEPT" -e "-j ACCEPT" "$SIM/ebt" || exit 0
grep -q -x -F "$1" "$SIM/ipt" && echo $(($(cat "$SIM/ra_count") + 1)) > "$SIM/ra_count"
grep -v -x -F "$1" "$SIM/known" > "$SIM/known.n"; echo "$1" >> "$SIM/known.n"; mv "$SIM/known.n" "$SIM/known"
EOF
	cat > "$SIM/bin/uradvd" <<'EOF'
#!/bin/sh
echo "$* | drop: $(cat "$SIM/drop")" >> "$SIM/uradvd"
EOF
	fast_sleep
	chmod +x "$SIM/bin/"*
}

# The script does not wait in the simulation
fast_sleep() { printf '#!/bin/sh\nexit 0\n' > "$SIM/bin/sleep"; chmod +x "$SIM/bin/sleep"; }
slow_sleep() { printf '#!/bin/sh\n/bin/sleep 0.05\n' > "$SIM/bin/sleep"; }

at() { echo "$1.00 0.00" > "$SIM/uptime"; }
run() { PATH="$SIM/bin:$PATH" sh "$SIM/filter" >/dev/null 2>&1; }
ra() { PATH="$SIM/bin:$PATH" "$SIM/bin/ra" "$1"; }
up() { echo "$1" >> "$SIM/alive"; }
down() { grep -v -x -F "$1" "$SIM/alive" > "$SIM/alive.n"; mv "$SIM/alive.n" "$SIM/alive"; }
in_fallback() { grep -q -x -e '-j ACCEPT' "$SIM/ebt"; }
job_pid() { cat "$SIM/ffmuc-ipv6-ra-filter.deprecate.job" 2>/dev/null; }
job_alive() { [ -n "$1" ] && kill -0 "$1" 2>/dev/null; }
# Wait until the background job of deprecate_old_prefixes ends
wait_job() {
	j=$(job_pid)
	for _ in $(seq 100); do job_alive "$j" || return 0; /bin/sleep 0.1; done
}
routes() { PATH="$SIM/bin:$PATH" ip -6 route show default dev br-client; }

check() {
	if eval "$2"; then
		echo "  ok:   $1"
	else
		echo "  FAIL: $1"
		FAIL=1
	fi
}

final_state() {
	check "no fallback" '! in_fallback'
	check "the filter accepts only the router of the selected gateway" \
		'[ "$(cat "$SIM/ebt")" = "-s $R1 -j ACCEPT" ]'
	check "odhcp6c knows only the router of the selected gateway" '[ "$(cat "$SIM/known")" = "$R1" ]'
	check "one default route, through the selected gateway" \
		'[ "$(routes | wc -l)" -eq 1 ] && routes | grep -q "fe80::$(echo "$R1" | tr -d :) "'
}

echo "1. The router of the selected gateway starts late. The fallback starts,"
echo "   then a router advertisement of the selected gateway arrives."
setup
up "$R2"
echo "$O1" > "$SIM/gw"
at 100; run                   # gateway change: router solicitation, no answer
at 110; run                   # second router solicitation, no answer
check "no fallback before FALLBACK_DELAY" '! in_fallback'
at 130; run                   # fallback: accept all, R2 answers
check "fallback after FALLBACK_DELAY" 'in_fallback'
check "default route through the other router during the fallback" '[ "$(tail -n 1 "$SIM/known")" = "$R2" ]'
at 135; up "$R1"; ra "$R1"    # the router of the selected gateway starts
at 138; ra "$R2"              # netifd installs the route of R2 again
at 140; run                   # timer during the fallback
at 150; ra "$R2"; run
final_state
sed 's/^/    /' "$SIM/log"

echo "2. The router of the selected gateway starts 3 s after the gateway change."
setup
up "$R2"
echo "$O1" > "$SIM/gw"
at 100; run
at 103; up "$R1"              # no unsolicited router advertisement before 160
at 110; run                   # second router solicitation: R1 answers
at 130; run
check "no fallback at any time" '! grep -q "Accepting all" "$SIM/log"'
final_state

echo "3. The router advertisements of the selected gateway stop, then come back."
setup
up "$R1"; up "$R2"
echo "$O1" > "$SIM/gw"
at 100; run
at 120; ra "$R1"; run
down "$R1"                    # its router advertisements stop, the route stays
at 430; run
check "fallback after RA_TIMEOUT" 'in_fallback'
at 435; up "$R1"; ra "$R1"; ra "$R2"
at 440; run
final_state

echo "4. The gateway changes. The node deprecates the prefix of the old router"
echo "   on its clients."
setup
up "$R1"; up "$R2"
echo "$O2" > "$SIM/gw"
at 100; run                   # first gateway: no old prefix
wait_job
check "no router advertisement at the first gateway" '[ ! -s "$SIM/uradvd" ]'
echo "$O1" > "$SIM/gw"
at 200; run; wait_job
check "uradvd deprecates only the old prefix" \
	'grep -q -e "--default-lifetime 0 --preferred-lifetime 0 --valid-lifetime 600 .* -a 2001:db8:2::/64 |" "$SIM/uradvd" &&
	! grep -q "2001:db8:1::" "$SIM/uradvd" && [ "$(wc -l < "$SIM/uradvd")" -eq 1 ]'
check "the node drops its own router advertisements while uradvd runs" \
	'grep -q "| drop: INPUT -i br-client -s fe80::1 -p ipv6-icmp --icmpv6-type router-advertisement -j DROP$" "$SIM/uradvd"'
check "the drop rule is removed after uradvd" '[ ! -s "$SIM/drop" ]'
final_state

echo "5. The new router announces the same prefix. The node deprecates nothing."
setup
printf '%s 2001:db8:1::/64\n%s 2001:db8:1::/64\n' "$R1" "$R2" > "$SIM/prefix"
up "$R1"; up "$R2"
echo "$O2" > "$SIM/gw"
at 100; run
echo "$O1" > "$SIM/gw"
at 200; run; wait_job
check "no uradvd" '[ ! -s "$SIM/uradvd" ]'

echo "6. The gateway changes again before the new router answers. The old job"
echo "   does not deprecate the prefix of the new gateway."
setup
up "$R2"
echo "$O2" > "$SIM/gw"
at 100; run
echo "$O1" > "$SIM/gw"        # R1 is down: no new prefix, the job waits
slow_sleep
at 200; run
job=$(job_pid)
check "the job waits for a new prefix" 'job_alive "$job"'
echo "$O2" > "$SIM/gw"        # back to the first gateway
at 205; run
/bin/sleep 0.2
check "the old job is stopped" '! job_alive "$job"'
fast_sleep
wait_job
check "no uradvd" '[ ! -s "$SIM/uradvd" ]'

rm -rf "$SIM"
if [ "$FAIL" = 0 ]; then echo "All tests passed."; else echo "Some tests failed."; fi
exit "$FAIL"

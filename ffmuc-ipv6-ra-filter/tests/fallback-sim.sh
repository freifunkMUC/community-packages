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
OWN=02:00:00:00:00:01

FAIL=0
SIM=""

setup() {
	[ -n "$SIM" ] && rm -rf "$SIM"
	SIM=$(mktemp -d)
	export SIM
	mkdir "$SIM/bin"
	: > "$SIM/ebt"; : > "$SIM/ipt"; : > "$SIM/known"; : > "$SIM/alive"; : > "$SIM/log"
	: > "$SIM/drop"; : > "$SIM/uradvd"; : > "$SIM/goodbye"
	mkdir -p "$SIM/brif/bat0" "$SIM/brif/local-port" "$SIM/brif/client0" "$SIM/brif/eth0.1"
	echo "$OWN" > "$SIM/braddr"
	printf '%s 2001:db8:1::/64\n%s 2001:db8:2::/64\n' "$R1" "$R2" > "$SIM/prefix"
	echo 0 > "$SIM/ra_count"
	echo "0.00 0.00" > "$SIM/uptime"
	printf '* %s -1 [.......] ( 1) %s ( 1) (0x1)\n* %s -1 [.......] ( 1) %s ( 1) (0x2)\n' \
		"$R1" "$O1" "$R2" "$O2" > "$SIM/tg"
	sed -e "s#/proc/uptime#$SIM/uptime#" -e "s#/tmp/ffmuc#$SIM/ffmuc#g" -e "s#/var/lock/#$SIM/#" \
		-e "s#/var/run/#$SIM/#" -e "s#/usr/sbin/uradvd#$SIM/bin/uradvd#" \
		-e "s#/lib/gluon/ffmuc-ipv6-ra-filter/ra-goodbye#$SIM/bin/ra-goodbye#" \
		-e "s#/sys/class/net/br-client/brif#$SIM/brif#" \
		-e "s#/sys/class/net/br-client/address#$SIM/braddr#" \
		-e "s#/etc/ffmuc-ipv6-ra-filter.last#$SIM/last#" \
		-e "s#/tmp/range6#$SIM/range6#" -e "s#/tmp/parker-sites/#$SIM/#" \
		-e 's#< "/proc/$pid/cmdline"#< "$SIM/proc/$pid/cmdline"#' \
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
# A run waits while another run holds the lock
if [ "$1" = -u ]; then rmdir "$2.d" 2>/dev/null; exit 0; fi
while ! mkdir "$1.d" 2>/dev/null; do /bin/sleep 0.02; done
EOF
	cat > "$SIM/bin/batctl" <<'EOF'
#!/bin/sh
case "$1" in
gw_mode) cat "$SIM/mode" 2>/dev/null || echo client ;;
gwl) [ -s "$SIM/gw" ] && echo "* $(cat "$SIM/gw") ( 255) x [ primary0]: 10.0/2.0 MBit" ;;
tg) cat "$SIM/tg" ;;
esac
EOF
	cat > "$SIM/bin/uci" <<'EOF'
#!/bin/sh
case "$3" in
network.client6.proto) cat "$SIM/proto6" 2>/dev/null || echo dhcpv6 ;;
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
done
# The own static prefix of an uplink
[ -s "$SIM/ownroute" ] && echo "$(cat "$SIM/ownroute") proto static metric 256 pref medium" ;;
"-6 addr show dev br-client scope link") echo "    inet6 fe80::1/64 scope link" ;;
"-6 neigh show dev br-client to "*) [ -f "$SIM/nolladdr" ] && { echo "$7 router FAILED"; exit; }; echo "$7 lladdr $(echo "$7" | sed 's/fe80:://; s/\(..\)/\1:/g; s/:$//') router REACHABLE" ;;
esac
EOF
	cat > "$SIM/bin/ifup" <<'EOF'
#!/bin/sh
echo "$(cut -d. -f1 "$SIM/uptime") ifup $1" >> "$SIM/log"
# A slow DHCPv4 renewal (ifup, firewall reload): wait until the test releases it
if [ "$1" = client ] && [ -f "$SIM/slow" ]; then
	while [ ! -f "$SIM/release" ]; do /bin/sleep 0.05; done
fi
[ "$1" = client6 ] || exit 0
# odhcp6c restarts: it forgets all routers and sends a router solicitation
: > "$SIM/known"
# The solicitation fails (firewall reload): once, or as many times as the
# file says
if [ -f "$SIM/eperm" ]; then
	n=$(($(cat "$SIM/eperm" 2>/dev/null || echo 1) - 1))
	[ "$n" -gt 0 ] && echo "$n" > "$SIM/eperm" || rm "$SIM/eperm"
	exit 0
fi
for mac in $(cat "$SIM/alive"); do "$SIM/bin/ra" "$mac"; done
EOF
	cat > "$SIM/bin/ra" <<'EOF'
#!/bin/sh
# A router advertisement from $1 arrives at the node
grep -q -x -e "-s $1 -j ACCEPT" -e "-j ACCEPT" "$SIM/ebt" || exit 0
grep -q -x -F "$1" "$SIM/ipt" && echo $(($(cat "$SIM/ra_count") + 1)) > "$SIM/ra_count"
# odhcp6c does not run: the kernel counts the router advertisement, but the
# node learns no route and no prefix
[ -f "$SIM/dead" ] && exit 0
grep -v -x -F "$1" "$SIM/known" > "$SIM/known.n"; echo "$1" >> "$SIM/known.n"; mv "$SIM/known.n" "$SIM/known"
EOF
	cat > "$SIM/bin/pidof" <<'EOF'
#!/bin/sh
ls "$SIM/proc" 2>/dev/null
EOF
	cat > "$SIM/bin/ra-goodbye" <<'EOF'
#!/bin/sh
echo "$*" >> "$SIM/goodbye"
EOF
	cat > "$SIM/bin/uradvd" <<'EOF'
#!/bin/sh
echo "$* | drop: $(cat "$SIM/drop")" >> "$SIM/uradvd"
EOF
	fast_sleep
	chmod +x "$SIM/bin/"*
}

# The script does not wait in the simulation
# "sleep 8" is the uradvd run of the deprecation job. Give the mocked uradvd
# time to write its log before the job stops it.
fast_sleep() { printf '#!/bin/sh\n[ "$1" = 8 ] && /bin/sleep 0.3\nexit 0\n' > "$SIM/bin/sleep"; chmod +x "$SIM/bin/sleep"; }
slow_sleep() { printf '#!/bin/sh\n[ "$1" = 8 ] && /bin/sleep 0.3\n/bin/sleep 0.05\n' > "$SIM/bin/sleep"; }

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
	for _ in $(seq 300); do job_alive "$j" || return 0; /bin/sleep 0.1; done
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
check "router lifetime 0 for the old router, only the old prefix, only on the client ports" \
	'[ "$(cat "$SIM/goodbye")" = "-s fe80::525400aa0600 -m $R2 -n 3 -t 3 -p 2001:db8:2::/64 client0 eth0.1" ]'
check "no uradvd on br-client: nothing goes into the mesh (bat0)" '[ ! -s "$SIM/uradvd" ]'
check "no drop rule" '[ ! -s "$SIM/drop" ]'
final_state

echo "5. The new router announces the same prefix. The node deprecates nothing."
setup
printf '%s 2001:db8:1::/64\n%s 2001:db8:1::/64\n' "$R1" "$R2" > "$SIM/prefix"
up "$R1"; up "$R2"
echo "$O2" > "$SIM/gw"
at 100; run
echo "$O1" > "$SIM/gw"
at 200; run; wait_job
check "no deprecation" '[ ! -s "$SIM/goodbye" ] && [ ! -s "$SIM/uradvd" ]'

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
check "no deprecation" '[ ! -s "$SIM/goodbye" ] && [ ! -s "$SIM/uradvd" ]'

# The router advertisement daemon of the gateway: $1 is its command line
daemon() { mkdir -p "$SIM/proc/100"; printf '%s' "$1" | tr ' ' '\0' > "$SIM/proc/100/cmdline"; }

echo "7. An uplink was a gateway client of O2 and becomes a gateway again. It"
echo "   deprecates the prefix of O2 on its clients and keeps its router lifetime."
setup
up "$R2"
echo "$O2" > "$SIM/gw"
at 100; run                   # gateway client: R2 gives 2001:db8:2::/64
check "check again soon (4 s after the renewal)" '[ "$(cat "$SIM/timer" 2>/dev/null)" = 4 ]'
at 110; run
echo server > "$SIM/mode"
printf '2001:db8:1::/64\n' > "$SIM/range6"
daemon "uradvd -i br-client --default-lifetime 180 -a 2001:db8:1::/64"
mkdir -p "$SIM/proc/101"      # ragoodbye: it is not the daemon
printf 'uradvd -i br-client --default-lifetime 0 --preferred-lifetime 0 -a x' | tr ' ' '\0' > "$SIM/proc/101/cmdline"
at 200; run; wait_job
check "uradvd deprecates only the old prefix, with the router lifetime of the daemon" \
	'grep -q -e "^-i br-client --default-lifetime 180 --preferred-lifetime 0 --valid-lifetime 0 .* -a 2001:db8:2::/64 |" "$SIM/uradvd" &&
	! grep -q "2001:db8:1::" "$SIM/uradvd" && [ "$(wc -l < "$SIM/uradvd")" -eq 1 ]'
check "router lifetime 0 in the name of the router of O2, only on the client ports" \
	'[ "$(cat "$SIM/goodbye")" = "-s fe80::525400aa0600 -m $R2 -n 3 -t 3 -p 2001:db8:2::/64 client0 eth0.1" ]'
check "the filter does not filter router advertisements" 'grep -q -x -e "-j RETURN" "$SIM/ebt"'
at 300; run; wait_job
check "only one deprecation" '[ "$(wc -l < "$SIM/uradvd")" -eq 1 ]'

echo "8. Multi-site uplink: the own prefixes come from the parker-sites state."
setup
up "$R2"
echo "$O2" > "$SIM/gw"
at 100; run; at 110; run
echo server > "$SIM/mode"
printf '2001:db8:3::/64,0,600\n2001:db8:2::/64,1800,600\n' > "$SIM/ra-state"
daemon "uradvd -i br-client --state-file x --default-lifetime 180"
at 200; run; wait_job
check "no uradvd: the uplink announces the same prefix" '[ ! -s "$SIM/uradvd" ]'

echo "9. No router advertisement daemon runs on the uplink. The job does not send"
echo "   router lifetime 0 from the router address."
setup
up "$R2"
echo "$O2" > "$SIM/gw"
at 100; run; at 110; run
echo server > "$SIM/mode"
printf '2001:db8:1::/64\n' > "$SIM/range6"
at 200; run; wait_job
check "no uradvd" '[ ! -s "$SIM/uradvd" ]'

echo "10. batman-adv sends the gw uevent before it sets the server mode. The"
echo "    script checks again soon."
setup
up "$R2"
echo "$O2" > "$SIM/gw"
at 100; run; at 110; run
: > "$SIM/gw"
at 200; run
check "check again after 3 s" '[ "$(cat "$SIM/timer" 2>/dev/null)" = 3 ]'
echo server > "$SIM/mode"
printf '2001:db8:1::/64\n' > "$SIM/range6"
daemon "uradvd -i br-client --default-lifetime 180 -a 2001:db8:1::/64"
at 203; run; wait_job
check "uradvd deprecates the old prefix" 'grep -q -e "-a 2001:db8:2::/64 |" "$SIM/uradvd"'

echo "11. The gateway changes while the old gateway is alive. The clients have a"
echo "    default route through the old router, and it drops the new source"
echo "    addresses. The node removes the old router on its local clients."
setup
up "$R1"; up "$R2"
echo "$O2" > "$SIM/gw"
at 100; run; wait_job
check "no router lifetime 0 at the first gateway" '[ ! -s "$SIM/goodbye" ]'
echo "$O1" > "$SIM/gw"
at 200; run; wait_job
check "router lifetime 0 from the link-local and MAC address of the old router" \
	'[ "$(cat "$SIM/goodbye")" = "-s fe80::525400aa0600 -m $R2 -n 3 -t 3 -p 2001:db8:2::/64 client0 eth0.1" ]'
check "not into the mesh (bat0) and not to the node (local-port)" \
	'! grep -q -e bat0 -e local-port "$SIM/goodbye"'
check "not in the name of the new router" '! grep -q "$R1" "$SIM/goodbye"'
check "no uradvd on br-client" '[ ! -s "$SIM/uradvd" ]'
final_state

echo "12. The MAC address of the old router is not known. The node does not send"
echo "    router lifetime 0 in its name."
setup
up "$R1"; up "$R2"
: > "$SIM/nolladdr"
echo "$O2" > "$SIM/gw"
at 100; run
echo "$O1" > "$SIM/gw"
at 200; run; wait_job
check "the node deprecates the old prefix from its own address, only on the client ports" \
	'[ "$(cat "$SIM/goodbye")" = "-s fe80::1 -m $OWN -v 600 -n 3 -t 3 -p 2001:db8:2::/64 client0 eth0.1" ]'
check "no uradvd on br-client" '[ ! -s "$SIM/uradvd" ]'

echo "13. The node has no local client port. It sends nothing in the name of the"
echo "    old router."
setup
rm -r "$SIM/brif/client0" "$SIM/brif/eth0.1"
up "$R1"; up "$R2"
echo "$O2" > "$SIM/gw"
at 100; run
echo "$O1" > "$SIM/gw"
at 200; run; wait_job
check "nothing sent" '[ ! -s "$SIM/goodbye" ] && [ ! -s "$SIM/uradvd" ]'

echo "14. After the gateway change, odhcp6c on the node fails (firewall reload)."
echo "    The node sends the router removal at the first router advertisement of"
echo "    the new router, and solicits again after 3 s."
setup
up "$R1"; up "$R2"
echo "$O2" > "$SIM/gw"
at 100; run; wait_job
: > "$SIM/eperm"; : > "$SIM/dead"
slow_sleep
echo "$O1" > "$SIM/gw"
at 200; run
/bin/sleep 0.3
check "no router removal before the new router answers" '[ ! -s "$SIM/goodbye" ]'
ra "$R1"                      # periodic router advertisement of the new router
/bin/sleep 0.8
check "router removal at once, without the prefix on the node" \
	'[ "$(cat "$SIM/goodbye")" = "-s fe80::525400aa0600 -m $R2 -n 3 -t 3 -p 2001:db8:2::/64 client0 eth0.1" ]'
fast_sleep; wait_job
rm -f "$SIM/dead"
at 203; run
check "new router solicitation 3 s after the gateway change" 'grep -q "^203 ifup client6" "$SIM/log"'
final_state

echo "15. Reboot: the node selects a gateway \"from none\". It removes its last"
echo "    router (from flash) on its clients when that router is not the new one."
setup
up "$R1"; up "$R2"
echo "fe80::525400aa0600,$R2 |2001:db8:2::/64 " > "$SIM/last"
echo "$O1" > "$SIM/gw"
at 100; run; wait_job
check "router removal for the last router" \
	'[ "$(cat "$SIM/goodbye")" = "-s fe80::525400aa0600 -m $R2 -n 3 -t 3 -p 2001:db8:2::/64 client0 eth0.1" ]'
final_state
at 110; run
check "the new router is saved" 'grep -q "^fe80::525400aa0100,$R1 |2001:db8:1::/64 $" "$SIM/last"'
setup
up "$R1"; up "$R2"
echo "fe80::525400aa0100,$R1 |2001:db8:1::/64 " > "$SIM/last"
echo "$O1" > "$SIM/gw"
at 100; run; wait_job
check "no router removal when the last router is the new one" '[ ! -s "$SIM/goodbye" ]'

echo "16. Network reload of an uplink: a short client phase without a default"
echo "    route, then server again. It removes its last router on its clients."
setup
up "$R2"
echo "$O2" > "$SIM/gw"
at 100; run; at 110; run      # an earlier client phase: R2 is saved
echo server > "$SIM/mode"
printf '2001:db8:1::/64\n' > "$SIM/range6"
daemon "uradvd -i br-client --default-lifetime 180 -a 2001:db8:1::/64"
at 150; run; wait_job
: > "$SIM/goodbye"
rm "$SIM/mode"; : > "$SIM/nolladdr"
at 200; run; at 210; run      # the node has the prefix, but no router entry
echo server > "$SIM/mode"
at 211; run; wait_job
check "router removal for the last router" \
	'[ "$(cat "$SIM/goodbye")" = "-s fe80::525400aa0600 -m $R2 -n 3 -t 3 -p 2001:db8:2::/64 client0 eth0.1" ]'

echo "17. The uplink comes back. client6 is static with the own prefix before"
echo "    batman-adv is in server mode, and a run without a gateway comes first."
setup
up "$R2"
echo "$O2" > "$SIM/gw"
at 100; run; at 110; run      # gateway client: R2 gives 2001:db8:2::/64
echo static > "$SIM/proto6"   # noderoute: uplink active, network reload
: > "$SIM/known"; : > "$SIM/gw"
echo 2001:db8:1::/64 > "$SIM/ownroute"
at 200; run                   # gw uevent: no gateway, still client mode
echo server > "$SIM/mode"
printf '2001:db8:1::/64\n' > "$SIM/range6"
daemon "uradvd -i br-client --default-lifetime 180 -a 2001:db8:1::/64"
at 203; run; wait_job
check "uradvd deprecates the prefix of the old gateway, not the own prefix" \
	'grep -q -e "-a 2001:db8:2::/64 |" "$SIM/uradvd" && ! grep -q "2001:db8:1::" "$SIM/uradvd"'
check "router removal for the router of the old gateway" \
	'[ "$(cat "$SIM/goodbye")" = "-s fe80::525400aa0600 -m $R2 -n 3 -t 3 -p 2001:db8:2::/64 client0 eth0.1" ]'

echo "18. The selected gateway announces no client MAC address yet. The script"
echo "    checks again after 3 s and then accepts only its router."
setup
up "$R1"
cp "$SIM/tg" "$SIM/tg.full"; : > "$SIM/tg"
echo "$O1" > "$SIM/gw"
at 100; run
check "accept all while the translation table is empty" 'in_fallback'
check "check again after 3 s" '[ "$(cat "$SIM/timer" 2>/dev/null)" = 3 ]'
cp "$SIM/tg.full" "$SIM/tg"
at 103; run
check "the filter accepts only the router of the selected gateway" \
	'[ "$(cat "$SIM/ebt")" = "-s $R1 -j ACCEPT" ]'
check "the gateway change is handled" 'grep -q "ifup client6" "$SIM/log"'

echo "19. After the gateway change, the first two router solicitations fail"
echo "    (the DHCPv4 renewal and the new lease reload the firewall). The next"
echo "    one comes 6 s after the gateway change and gets the router."
setup
up "$R1"; up "$R2"
echo "$O2" > "$SIM/gw"
at 100; run; wait_job
echo 2 > "$SIM/eperm"         # ifup client6 at the change and at 3 s fail
echo "$O1" > "$SIM/gw"
at 200; run; wait_job
at 203; run
check "no default route after 2 failed solicitations" '[ ! -s "$SIM/known" ]'
at 206; run
check "new router solicitation 6 s after the gateway change" 'grep -q "^206 ifup client6" "$SIM/log"'
at 210; run
check "no solicitation at 10 s, the router is known" '! grep -q "^210 ifup client6" "$SIM/log"'
final_state

echo "20. The DHCPv4 renewal of the gateway change run takes 11 s (ifup and"
echo "    firewall reload). The timer runs in this time do not wait for it and"
echo "    send no router solicitation. After the renewal, the router"
echo "    solicitations come 3 s apart, not back to back."
setup
up "$R1"; up "$R2"
: > "$SIM/slow"
echo 1 > "$SIM/eperm"         # the router solicitation of the renewal fails
echo "$O1" > "$SIM/gw"
at 200; run & g=$!            # gateway change "from none"
/bin/sleep 0.5
at 204; run & t1=$!; /bin/sleep 0.5
at 207; run & t2=$!; /bin/sleep 0.5
at 210; run & t3=$!; /bin/sleep 0.5
check "the timer runs do not wait for the renewal" \
	'! kill -0 $t1 2>/dev/null && ! kill -0 $t2 2>/dev/null && ! kill -0 $t3 2>/dev/null'
check "no router solicitation while the renewal runs" '! grep -q "ifup client6" "$SIM/log"'
at 211; : > "$SIM/release"
wait $g $t1 $t2 $t3
check "one router solicitation, at the end of the renewal" '[ "$(grep -c "ifup client6" "$SIM/log")" = 1 ]'
check "next check 4 s after the renewal" '[ "$(cat "$SIM/timer" 2>/dev/null)" = 4 ]'
at 213; run
check "no router solicitation 2 s after the renewal" '[ "$(grep -c "ifup client6" "$SIM/log")" = 1 ]'
at 214; run
check "next router solicitation 3 s after the renewal" 'grep -q "^214 ifup client6" "$SIM/log"'
at 215; run
check "no router solicitation 1 s after the last one" '! grep -q "^215 ifup client6" "$SIM/log"'
final_state

rm -rf "$SIM"
if [ "$FAIL" = 0 ]; then echo "All tests passed."; else echo "Some tests failed."; fi
exit "$FAIL"

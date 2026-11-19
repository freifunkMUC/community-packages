#!/bin/sh
# shellcheck disable=SC2016
# Test of ra-goodbye with a real Linux kernel as client. Needs root and network
# namespaces, for example:
#   docker run --rm --privileged -v "$PWD":/w -w /w/ffmuc-ipv6-ra-filter \
#     alpine:3.20 sh tests/ra-goodbye-test.sh
#
# A router (radvd) gives the client a default route and an address. radvd stops
# without a final router advertisement. ra-goodbye then sends router lifetime 0
# from the address of the router: the client must remove the route and
# deprecate the address. A second port (the mesh) must not get the frame.

set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
apk add -q build-base linux-headers radvd tcpdump iproute2 >/dev/null
gcc -Wall -Wextra -Werror -O2 -o /tmp/ra-goodbye "$HERE/../src/ra-goodbye.c"

FAIL=0
check() {
	if eval "$2"; then echo "  ok:   $1"; else echo "  FAIL: $1"; FAIL=1; fi
}

ip netns add client
ip netns add mesh
ip link add port0 type veth peer name c0 netns client
ip link add mesh0 type veth peer name m0 netns mesh
ip netns exec client sysctl -q -w net.ipv6.conf.c0.accept_ra=2
for l in port0 mesh0; do ip link set "$l" up; done
ip netns exec client ip link set c0 up
ip netns exec mesh ip link set m0 up
sleep 2
LL=$(ip -6 addr show dev port0 scope link | awk '$1 == "inet6" { sub(/\/.*/, "", $2); print $2 }')
MAC=$(cat /sys/class/net/port0/address)

cat > /tmp/radvd.conf <<EOF
interface port0 {
	AdvSendAdvert on;
	MinRtrAdvInterval 3;
	MaxRtrAdvInterval 4;
	AdvDefaultLifetime 1800;
	prefix 2001:db8:2::/64 { AdvPreferredLifetime 1800; AdvValidLifetime 3600; };
};
EOF
radvd -C /tmp/radvd.conf -p /tmp/radvd.pid -m stderr
for _ in $(seq 20); do
	ip netns exec client ip -6 route show default | grep -q "via $LL" && break
	sleep 1
done
sleep 2
check "the client has a default route via the router" \
	'ip netns exec client ip -6 route show default | grep -q "via $LL"'
check "the client has an address of the prefix" \
	'ip netns exec client ip -6 addr show dev c0 | grep -q "2001:db8:2:"'
kill -9 "$(cat /tmp/radvd.pid)"

ip netns exec mesh tcpdump -i m0 -n -c 1 icmp6 > /tmp/mesh.txt 2>/dev/null &
dump=$!
tcpdump -i port0 -n -vv -c 1 'icmp6 and ip6[40] == 134' > /tmp/port.txt 2>/dev/null &
cap=$!
sleep 1
/tmp/ra-goodbye -s "$LL" -m "$MAC" -p 2001:db8:2::/64 -n 1 port0
sleep 1
kill "$cap" "$dump" 2>/dev/null || true
cat /tmp/port.txt
check "checksum ok, router lifetime 0, prefix lifetimes 0" \
	'grep -q "router lifetime 0s" /tmp/port.txt && grep -q "valid time 0s, pref. time 0s" /tmp/port.txt &&
	grep -q "icmp6 sum ok" /tmp/port.txt'
check "the client removed the default route" \
	'! ip netns exec client ip -6 route show default | grep -q "via $LL"'
check "the client deprecated the address" \
	'ip netns exec client ip -6 addr show dev c0 | grep "2001:db8:2:" | grep -q deprecated'
check "nothing on the mesh port" '! grep -q "router advertisement" /tmp/mesh.txt'
check "bad arguments are refused" '! /tmp/ra-goodbye -s 2001:db8::1 -m "$MAC" port0 2>/dev/null'

if [ "$FAIL" = 0 ]; then echo "All tests passed."; else echo "Some tests failed."; fi
exit "$FAIL"

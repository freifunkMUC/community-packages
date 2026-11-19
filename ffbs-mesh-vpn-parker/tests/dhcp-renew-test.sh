#!/bin/sh
# Test of /lib/gluon/ebtables/402-parker-dhcp-renew with the kernel bridge and
# ebtables. Needs root (network namespaces), ebtables, iproute2, lua5.1 and
# python3. Example:
#   docker run --rm --privileged -v "$PWD":/w alpine:3.20 sh -c \
#     'apk add -q ebtables iproute2 lua5.1 python3 && sh /w/tests/dhcp-renew-test.sh'
# A client on br-client sends a DHCPv4 request per unicast to another uplink
# through bat0. noderoute adds DROP to PARKER_DHCP when the node is active, and
# flushes the chain when the node is inactive.
set -e
DIR=$(cd "$(dirname "$0")/.." && pwd)
FAIL=0

cleanup() {
	ip netns del cl 2>/dev/null || true
	ip netns del up 2>/dev/null || true
	ip link del br-client 2>/dev/null || true
	ebtables -F FORWARD
	ebtables -X PARKER_DHCP 2>/dev/null || true
}
trap cleanup EXIT

# Load the rule file like gluon-ebtables does
RULES="$DIR/files/lib/gluon/ebtables/402-parker-dhcp-renew" lua5.1 -e '
function chain(name, policy) print("ebtables -N " .. name .. " -P " .. policy) end
function rule(r) print("ebtables -A " .. r) end
dofile(os.getenv("RULES"))' > /tmp/dhcp-renew-rules
sh -e /tmp/dhcp-renew-rules

ip link add br-client type bridge
ip netns add cl
ip netns add up
ip link add cl0 type veth peer name eth0 netns cl
ip link add bat0 type veth peer name eth0 netns up
for p in cl0 bat0; do ip link set "$p" master br-client up; done
ip link set br-client up
ip -n cl addr add 10.0.0.2/24 dev eth0
ip -n up addr add 10.0.0.1/24 dev eth0
for n in cl up; do ip -n "$n" link set eth0 up; ip -n "$n" link set lo up; done

# Sends one UDP packet from the client to the other uplink, port $1.
# Prints "received" when the uplink gets it.
send() {
	ip netns exec up python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.0.0.1", int(sys.argv[1])))
s.settimeout(2)
try:
	s.recv(100); print("received")
except socket.timeout:
	print("lost")' "$1" > /tmp/dhcp-renew-result &
	sleep 0.5
	ip netns exec cl python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.0.0.2", 68 if sys.argv[1] == "67" else 0))
for i in range(3): s.sendto(b"x", ("10.0.0.1", int(sys.argv[1])))' "$1"
	wait
	cat /tmp/dhcp-renew-result
}

check() {
	if [ "$(send "$2")" = "$3" ]; then echo "  ok:   $1"; else echo "  FAIL: $1"; FAIL=1; fi
}

echo "Inactive node (gateway client): PARKER_DHCP is empty"
check "DHCPv4 renewal goes through bat0 to the uplink" 67 received
echo "Active node (gateway server): PARKER_DHCP has DROP"
ebtables -A PARKER_DHCP -j DROP
check "DHCPv4 renewal to another uplink is dropped" 67 lost
check "other UDP traffic to the uplink goes through" 5000 received
echo "Node inactive again: PARKER_DHCP is flushed"
ebtables -F PARKER_DHCP
check "DHCPv4 renewal goes through bat0 again" 67 received

if [ "$FAIL" = 0 ]; then echo "All tests passed."; else echo "Some tests failed."; exit 1; fi

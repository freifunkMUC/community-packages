DHCPv4 after a gateway change
=============================

The node gives leases of 3 minutes to its clients. A client renews its
lease per unicast at the node that gave it, after half of the lease time.

A client of a routing node can still have a lease of another node, for
example from the time when its node did not route. The renewal goes
through the mesh to the other node. Thus the other node stays the IPv4
router of the client as long as it answers.

When the other node does not answer (it has stopped routing, or it is
off), the client sends its request as a broadcast after 87.5 % of the
lease time. batman-adv does not send a DHCP request of a client into the
mesh while the node is a gateway server. Thus only the node of the client
receives the broadcast.

dnsmasq is not authoritative (`/lib/gluon/upgrade/905-dhcp-not-authoritative`).
Thus it does not answer a broadcast request (rebinding or INIT-REBOOT) for
a lease that it does not know. It answers a unicast renewal of such a
lease with a DHCPNAK. At the end of the lease, the client sends a
DHCPDISCOVER and gets a new lease from its own node. Thus the client
changes to its own node at most 3 minutes after the other node stops
answering.

An authoritative dnsmasq answers a request for an address of its client
network with a DHCPACK for the same address, but with the router address
of this node. Some clients (Android 11) then lose their IPv4 default route
until they connect again.

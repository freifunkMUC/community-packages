# ffmuc-ipv6-ra-filter

The package accepts router advertisements from `bat0` only from the selected batman-adv gateway (`batctl gwl`). IPv4 and IPv6 then use the same gateway.

- The filter applies to the clients (`FORWARD`) and to the node itself (`INPUT`).
- A Gluon gateway sends its router advertisements from its client MAC address, not from its originator address. The filter accepts the wired client MAC addresses that the gateway announces in the translation table (`batctl tg`).
- When no gateway is selected, or the gateway announces no client MAC address, the filter accepts all router advertisements. The node then does not lose IPv6. The filter does not use router advertisements to select the router.
- Fallback: the filter also accepts all other routers when the node has no IPv6 default route through the selected gateway for 30 seconds, or when no router advertisement of the selected gateway arrives for 180 seconds (3 times the maximum router advertisement interval of 60 seconds). An ip6tables counter (mangle table, chain `ffmuc_ra_count`) counts the router advertisements of the selected gateway. After 10 seconds without a default route through the selected gateway, the node sends a new router solicitation (`ifup client6`), because the router of a new gateway can start after the first router solicitation. The fallback stops when a new router advertisement of the selected gateway arrives. The filter does not wait for a default route through it: during the fallback, odhcp6c knows all routers, and netifd installs only one of their default routes. The filter then runs `ifup client6`, so that odhcp6c forgets the other routers. The node then does not stay without IPv6 while another router announces a prefix.
- The filter is updated when batman-adv selects a new gateway (`gw` uevent), once per minute, and by a timer at the next fallback time (every 10 seconds during the fallback).
- When the gateway changes on a node without a static client address, the node requests a new DHCPv4 lease and restarts `client6`. The node then drops the addresses and the default route of the old router at once.
- After a gateway change, the node also tells its clients that the prefixes of the old router are deprecated. When a prefix of the new router arrives (at most 45 seconds), the node sends router advertisements for 8 seconds with `uradvd`: router lifetime 0, preferred lifetime 0 and valid lifetime 600 seconds for each old prefix that the new router does not announce. The clients then use an address of the new router for new connections. Old connections continue until the valid lifetime ends. Other mesh nodes and the uplinks drop these router advertisements, because they accept only the router of their gateway. While `uradvd` runs, an ip6tables rule (mangle table, `INPUT`) drops the router advertisements of the node itself, so that odhcp6c on the node does not add the old prefixes again. The node does nothing when `/usr/sbin/uradvd` does not exist.
- A node in batman-adv gateway mode (`batctl gw_mode` reports `server`) selects no gateway. On such a node the chain returns to `FORWARD` and `INPUT`. The package that makes the node a gateway (for example `ffbs-mesh-vpn-parker`) then handles the router advertisements.
- respondd reports the MAC address of the IPv6 default router of the node in `statistics.gateway6`. It reports nothing on a gateway node and when the node has no default router. Other packages also write `gateway6` (`ffbs-parker-respondd` reports the IPv6 address of its uplink), and respondd uses the value of the last module.

Do not install `gluon-radv-filterd` together with this package. Its chain accepts the router advertisements first.

### Tests

`sh tests/fallback-sim.sh` simulates the fallback with mock commands. It does not need a Gluon node. Run it with busybox `sh`, for example in an Alpine container.

### Credits

This is based on the FFMUC package [ffmuc-simple-radv-filter](https://github.com/freifunkMUC/gluon-packages/tree/7c2e1224c0cfc1e66f93738aefbcd401bfb11f2c/ffmuc-simple-radv-filter).

### Contact

Feel free to ask questions in the [FFMUC chat](https://chat.ffmuc.net).

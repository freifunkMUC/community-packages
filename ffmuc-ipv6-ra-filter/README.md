# ffmuc-ipv6-ra-filter

The package accepts router advertisements from `bat0` only from the selected batman-adv gateway (`batctl gwl`). IPv4 and IPv6 then use the same gateway.

- The filter applies to the clients (`FORWARD`) and to the node itself (`INPUT`).
- A Gluon gateway sends its router advertisements from its client MAC address, not from its originator address. The filter accepts the wired client MAC addresses that the gateway announces in the translation table (`batctl tg`).
- When no gateway is selected, or the gateway announces no client MAC address, the filter accepts all router advertisements. The node then does not lose IPv6. The filter does not use router advertisements to select the router.
- Fallback: when the node has no IPv6 default route through the selected gateway for 30 seconds, the filter also accepts all other routers. When the default route through the selected gateway is back, the filter accepts only the selected gateway again. The node then does not stay without IPv6 while another router announces a prefix. If the selected gateway stops its router advertisements, the fallback starts only after its default route expires (router lifetime).
- The filter is updated when batman-adv selects a new gateway (`gw` uevent), and once per minute.
- When the gateway changes on a node without a static client address, the node requests a new DHCPv4 lease and restarts `client6`. The node then drops the addresses and the default route of the old router at once.
- respondd reports the MAC address of the IPv6 default router of the node in `statistics.gateway6`.

Do not install `gluon-radv-filterd` together with this package. Its chain accepts the router advertisements first.

A node which is a gateway itself (`batctl gw_mode` reports `server`) never selects a gateway and therefore has nothing to filter for. On such a node the filter does not apply and returns to the `FORWARD` chain, which leaves the router advertisements to whatever configures the node as gateway.

The package also ships a `respondd` module which reports the MAC address the filter accepts router advertisements from as `statistics.gateway6`. It stays silent on a gateway node and whenever no gateway is known: `gateway6` is written by other packages as well (`ffbs-parker-respondd` reports the IPv6 address of its uplink there), and respondd lets the last module that writes a field win.

### Credits

This is based on the FFMUC package [ffmuc-simple-radv-filter](https://github.com/freifunkMUC/gluon-packages/tree/7c2e1224c0cfc1e66f93738aefbcd401bfb11f2c/ffmuc-simple-radv-filter).

### Contact

Feel free to ask questions in the [FFMUC chat](https://chat.ffmuc.net).

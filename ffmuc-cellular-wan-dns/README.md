ffmuc-cellular-wan-dns
======================

This package keeps DNS for gluon-wan-dnsmasq on nodes with a Gluon
cellular uplink (`cellular`, `cellular_4`).

gluon-wan-dnsmasq resolves names for the node itself, for example the
config server of Parker. It takes its servers from the uplinks in
`/lib/gluon/wan-dnsmasq/interface.d/`. When no uplink reports a server,
its server file is empty and name resolution fails.

Function
--------

* The hotplug script `51-ffmuc-cellular-wan-dns` runs after
  `50-gluon-wan-dnsmasq` for the same interfaces.
* When a cellular interface is up and no uplink reports a DNS server, the
  script writes the fallback list. The first line of the file is
  `# ffmuc-cellular-wan-dns fallback`.
* When an uplink reports DNS servers, gluon-wan-dnsmasq writes them and
  replaces the fallback list.
* The script does nothing on nodes without `network.cellular`, and when
  `gluon-wan-dnsmasq.@static[0].server` is set.

Configuration
-------------

`/etc/config/ffmuc-cellular-wan-dns`:

    config fallback 'fallback'
        option enabled '1'
        list server '5.1.66.255'
        list server '185.150.99.255'
        list server '2001:678:e68:f000::'
        list server '2001:678:ed0:f000::'

The default servers are the public FFMUC resolvers. Set `enabled` to `0`
to switch off the fallback.

Related fixes
-------------

* `ffbs-mesh-vpn-parker` sets `ip4table 1` on `cellular`. Without it,
  Parker cannot send DNS queries to IPv4 servers on the cellular uplink.
* On OpenWrt 24.10, the qmi and mbim proto handlers drop the DNS servers
  when `peerdns` is `0`. Gluon sets `peerdns 0`. A firmware patch fixes
  this. openwrt/openwrt#21314 fixes it in newer OpenWrt.

Tests
-----

    lua tests/update-test.lua [path/to/gluon-wan-dnsmasq/update.lua]

The test uses mock ubus, uci and files. With the path, it also runs the
update.lua of gluon-wan-dnsmasq.

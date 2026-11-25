ffmuc-dhcp-ap-controllers
=========================

This package tells UniFi and Omada access points the address of their
controller through DHCPv4. An access point can then find its controller
when the controller is not in its broadcast domain.

The package does not need Parker. It writes to the dnsmasq section
`client` (the DHCP server of the client network). It has no effect when
dnsmasq does not serve DHCP on the client network.

site.conf
---------

Both values are optional and take IPv4 addresses only:

    dhcp_ap_controllers = {
        unifi4 = '198.51.100.10',
        omada4 = { '198.51.100.11' },
    },

Function
--------

* UniFi: suboption 1 of the vendor-specific DHCPv4 option 43. dnsmasq
  sends it only to clients with the vendor class `ubnt`.
* Omada: DHCPv4 option 138, the CAPWAP access controller list (RFC 5417).
  It takes more than one address. dnsmasq sends it to each client that
  asks for option 138.
* When a value is not set, the package removes its option.

The code is in `/lib/gluon/upgrade/998-ffmuc-dhcp-ap-controllers`.

Tests
-----

    lua tests/upgrade-test.lua

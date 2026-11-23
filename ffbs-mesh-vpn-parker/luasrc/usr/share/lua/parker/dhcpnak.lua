-- Send our old DHCPv4 clients to the new uplink at once.
--
-- When this node stops routing for its clients, they keep their lease and
-- renew it per unicast with our old client address. Without an answer they
-- only look for a new server when the lease runs out. This module keeps the
-- old address on br-client for HOLD seconds and lets dnsmasq answer each
-- renewal with a DHCPNAK. The client then starts again with a DHCPDISCOVER,
-- which only the active uplinks answer.
--
-- dnsmasq sends a DHCPNAK for an address in a "static" range that it has not
-- assigned, and it ignores a DHCPDISCOVER for such a range.
--
-- With 464XLAT, the config service can give all uplinks the same client
-- address (see clientaddr.lua). When another node uses the address (an
-- uplink that has become active), we must not hold it: two nodes would
-- answer ARP for the router of the clients, and our dnsmasq would NAK the
-- requests for the other node. In this case only, we do not start, and we
-- stop at the next check, when batman-adv has seen another node with the
-- address. Without 464XLAT, each node has its own range4, and we always
-- hold the address for HOLD seconds.

local clientaddr = require("clientaddr")
local util = require("util")

local dhcpnak = {}

-- Longer than a lease (2m, see noderoute.lua), so that each old client
-- renews at least once while we hold the address.
dhcpnak.HOLD = 150

local IFACE = "br-client"
local STATE_FILE = "/tmp/parker-dhcp-nak"
local CONF_NAME = "parker-dhcp-nak.conf"

-- The directories that dnsmasq reads with conf-dir, from the config files
-- that /etc/init.d/dnsmasq generates.
local function conf_dirs()
	local dirs = {}
	local p = io.popen("cat /var/etc/dnsmasq.conf.* 2>/dev/null")
	for line in p:lines() do
		local dir = line:match("^conf%-dir=([^,]+)")
		if dir then
			table.insert(dirs, dir)
		end
	end
	p:close()
	return dirs
end

-- "10.80.96.13/20" -> "10.80.96.13", "10.80.96.0", "255.255.240.0"
function dhcpnak.parse(cidr)
	local a, b, c, d, len = (cidr or ""):match("^(%d+)%.(%d+)%.(%d+)%.(%d+)/(%d+)$")
	len = tonumber(len)
	if not a or len > 32 then
		return nil
	end
	local octets = { tonumber(a), tonumber(b), tonumber(c), tonumber(d) }
	local net, mask = {}, {}
	for i = 1, 4 do
		local bits = math.max(0, math.min(8, len - 8 * (i - 1)))
		local block = 2 ^ (8 - bits)
		mask[i] = string.format("%d", 256 - block)
		net[i] = string.format("%d", octets[i] - octets[i] % block)
	end
	return table.concat(octets, "."), table.concat(net, "."), table.concat(mask, ".")
end

local function set_conf(content)
	for _, dir in ipairs(conf_dirs()) do
		local path = dir .. "/" .. CONF_NAME
		if content then
			util.write_file(path, content)
		else
			os.remove(path)
		end
	end
	os.execute("/etc/init.d/dnsmasq restart")
end

-- Start to NAK the renewals for the client network of cidr, our old client
-- address with its prefix length. shared: other nodes can have the same
-- address (464XLAT).
function dhcpnak.start(cidr, shared)
	local addr, net, mask = dhcpnak.parse(cidr)
	if not addr then
		return false
	end
	local claim = shared and clientaddr.claim(addr)
	if claim then
		util.log("DHCP: " .. addr .. " is in use by " .. claim .. ". No DHCPNAK.")
		return false
	end
	os.execute("ip addr replace " .. addr .. "/32 dev " .. IFACE)
	set_conf("dhcp-authoritative\ndhcp-range=set:parker-nak," .. net .. ",static," .. mask .. "\n")
	util.write_file(STATE_FILE, addr .. " " .. os.time() .. (shared and " shared" or ""))
	util.log("DHCP: sending DHCPNAK to the clients of " .. addr .. " for " .. dhcpnak.HOLD .. "s")
	return true
end

function dhcpnak.stop()
	local state = util.read_file(STATE_FILE)
	if not state then
		return
	end
	local addr = state:match("^(%S+)")
	os.remove(STATE_FILE)
	if addr then
		os.execute("ip addr del " .. addr .. "/32 dev " .. IFACE .. " 2>/dev/null")
	end
	set_conf(nil)
	util.log("DHCP: no more DHCPNAK for the clients of " .. tostring(addr))
end

-- Stop after HOLD seconds, or when another node uses a shared address.
function dhcpnak.expire()
	local state = util.read_file(STATE_FILE)
	if not state then
		return
	end
	local addr, since, flag = state:match("^(%S+) (%d+) ?(%S*)")
	since = tonumber(since)
	if not since or os.time() - since >= dhcpnak.HOLD then
		dhcpnak.stop()
		return
	end
	local claim = flag == "shared" and clientaddr.claim(addr)
	if claim then
		util.log("DHCP: " .. addr .. " is in use by " .. claim)
		dhcpnak.stop()
	end
end

return dhcpnak

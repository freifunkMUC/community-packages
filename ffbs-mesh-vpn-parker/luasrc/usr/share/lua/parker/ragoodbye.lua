-- Tell the clients that this node is no longer their router.
--
-- When the node stops routing for its clients, its last router
-- advertisement is still valid on the clients for up to the router
-- lifetime. In this time they send traffic to a node that cannot route
-- it. This module sends some router advertisements with router lifetime
-- 0 and preferred lifetime 0 for each prefix. The clients then drop this
-- node as router at once and use the router of another uplink.
--
-- Send before the node leaves gateway mode: the mesh nodes only pass on
-- router advertisements of the selected gateway (ffmuc-ipv6-ra-filter).

local util = require("util")

local ragoodbye = {}

local IFACE = "br-client"
-- uradvd sends one RA at start and the next ones 3 to 4 s apart.
ragoodbye.DURATION = 8
-- Lower than the valid lifetime on the clients: they ignore a lower valid
-- lifetime (RFC 4862, 5.5.3 e) and keep the prefix as deprecated.
local VALID = 600
local MULTISITE_STATE = "/tmp/parker-sites/ra-state"
local RANGE6_FILE = "/tmp/range6"

-- The prefixes this node announces: of all sites, else the single one.
function ragoodbye.prefixes()
	local result = {}
	for line in (util.read_file(MULTISITE_STATE) or ""):gmatch("[^\n]+") do
		local prefix = line:match("^([%x:]+/%d+),")
		if prefix then
			table.insert(result, prefix)
		end
	end
	if #result == 0 then
		local prefix = (util.read_file(RANGE6_FILE) or ""):match("^%s*([%x:]+/%d+)")
		if prefix then
			table.insert(result, prefix)
		end
	end
	return result
end

function ragoodbye.command(prefixes)
	local cmd = "/usr/sbin/uradvd -i " .. IFACE
		.. " --default-lifetime 0 --preferred-lifetime 0 --valid-lifetime " .. VALID
		.. " --min-router-adv-interval 3 --max-router-adv-interval 4"
	for _, prefix in ipairs(prefixes) do
		cmd = cmd .. " -a " .. prefix
	end
	return cmd
end

-- Stop the RA daemons first, then send for DURATION seconds. Returns false
-- if there is nothing to announce.
function ragoodbye.send()
	os.execute("/etc/init.d/parker-radvd stop >/dev/null 2>&1")
	os.execute("/etc/init.d/gluon-radvd stop >/dev/null 2>&1")
	local prefixes = ragoodbye.prefixes()
	if #prefixes == 0 then
		return false
	end
	util.log("RA: router lifetime 0 for " .. table.concat(prefixes, " ") .. " (" .. ragoodbye.DURATION .. "s)")
	os.execute(ragoodbye.command(prefixes) .. " >/dev/null 2>&1 & pid=$!; sleep "
		.. ragoodbye.DURATION .. "; kill $pid")
	return true
end

return ragoodbye

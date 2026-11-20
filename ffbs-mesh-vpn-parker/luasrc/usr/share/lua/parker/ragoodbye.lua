-- Tell the clients that this node is no longer their router.
--
-- When the node stops routing for its clients, its last router
-- advertisement is still valid on the clients for up to the router
-- lifetime. This module stops the router advertisement daemons and starts
-- /usr/sbin/parker-ra-goodbye in the background. That script waits until
-- the node has a default route through a new router on br-client. Then it
-- sends some router advertisements with router lifetime 0 and preferred
-- lifetime 0 for each prefix. The clients then drop this node as router and
-- use the new router.
--
-- Do not send router lifetime 0 before a new router is there: a client
-- without a default router sees a loss of provisioning, and Android 15
-- with CLAT (IPv6-only) then disconnects from the Wi-Fi. If no new router
-- comes in WAIT seconds, the script sends nothing: the router lifetime on
-- the clients (180 s) ends by itself, and if the uplink comes back before,
-- the clients continue without a change.
--
-- The clients of the other mesh nodes do not need this: when they select a
-- new gateway, ffmuc-ipv6-ra-filter on their node removes this router after
-- the new router is there.

local util = require("util")

local ragoodbye = {}

-- uradvd sends one RA at start and the next ones 3 to 4 s apart.
ragoodbye.DURATION = 8
-- Lower than the valid lifetime on the clients: they ignore a lower valid
-- lifetime (RFC 4862, 5.5.3 e) and keep the prefix as deprecated.
local VALID = 600
-- The router lifetime of parker-radvd (parker-sites.lua) and of uradvd.
ragoodbye.WAIT = 180
ragoodbye.SCRIPT = "/usr/sbin/parker-ra-goodbye"
ragoodbye.PID_FILE = "/tmp/parker-ra-goodbye.pid"
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
	local cmd = ragoodbye.SCRIPT .. " " .. ragoodbye.WAIT .. " " .. ragoodbye.DURATION .. " " .. VALID
	for _, prefix in ipairs(prefixes) do
		cmd = cmd .. " " .. prefix
	end
	return cmd
end

-- Stop a waiting or sending goodbye, before the node routes again.
function ragoodbye.cancel()
	local pid = tonumber((util.read_file(ragoodbye.PID_FILE) or ""):match("%d+"))
	if not pid then
		return false
	end
	local cmdline = util.read_file("/proc/" .. pid .. "/cmdline") or ""
	if not cmdline:find("parker-ra-goodbye", 1, true) then
		os.remove(ragoodbye.PID_FILE)
		return false
	end
	util.log("RA: cancel the router lifetime 0 (pid " .. pid .. ")")
	os.execute("kill " .. pid .. " 2>/dev/null")
	-- The script stops its uradvd at once. Wait for it (at most 3 s).
	os.execute("i=0; while [ -d /proc/" .. pid .. " ] && [ $i -lt 3 ]; do sleep 1; i=$((i + 1)); done")
	return true
end

-- Stop the RA daemons, then start the goodbye in the background. Returns
-- false if there is nothing to announce.
function ragoodbye.send()
	os.execute("/etc/init.d/parker-radvd stop >/dev/null 2>&1")
	os.execute("/etc/init.d/gluon-radvd stop >/dev/null 2>&1")
	ragoodbye.cancel()
	local prefixes = ragoodbye.prefixes()
	if #prefixes == 0 then
		return false
	end
	util.log("RA: router lifetime 0 for " .. table.concat(prefixes, " ")
		.. " when a new router is there (at most " .. ragoodbye.WAIT .. "s)")
	os.execute(ragoodbye.command(prefixes) .. " >/dev/null 2>&1 &")
	return true
end

return ragoodbye

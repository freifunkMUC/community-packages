-- The tunnels noderoute can use. noderoute.lua and noderoute.sh both use
-- these rules.

local stat = require("posix.sys.stat")
local util = require("util")

-- A tunnel is usable when its last handshake is less than this old.
local HANDSHAKE_MAX_AGE = 180

-- Multi-site operation: parker-sites writes this status each second. Use
-- only a recent status.
local SITES_STATUS = "/tmp/parker-sites/status"
local SITES_STATUS_MAX_AGE = 30

local M = {}

local function usable(wg, now)
	-- The wg interfaces with one peer and a recent handshake, sorted.
	local result = {}
	for iface, data in pairs(wg) do
		if util.tablelength(data.peers) == 1 then
			local _, peer = next(data.peers)
			if now - peer.latest_handshake < HANDSHAKE_MAX_AGE then
				table.insert(result, iface)
			end
		end
	end
	table.sort(result)
	return result
end

local function no_site_up(now)
	local st = stat.stat(SITES_STATUS)
	if not st or now - st.st_mtime > SITES_STATUS_MAX_AGE then
		return false
	end
	return (util.read_file(SITES_STATUS) or ""):find("\nactive=nil\n", 1, true) ~= nil
end

function M.active()
	-- The usable tunnels. When parker-sites finds no site up, returns no
	-- tunnels and true.
	local now = os.time()
	local result = usable(util.get_wg_info(), now)
	if #result > 0 and no_site_up(now) then
		return {}, true
	end
	return result, false
end

function M.key()
	-- Changes when the result of active() can change.
	local now = os.time()
	local key = table.concat(usable(util.get_wg_info(), now), " ")
	if no_site_up(now) then
		key = key .. " no-site-up"
	end
	return key
end

return M

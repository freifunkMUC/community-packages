-- Which tunnels noderoute may route through. noderoute.lua makes its
-- decision with these rules, and noderoute.sh asks for key() to see when
-- that decision may change, so both always use the same rules.

local stat = require("posix.sys.stat")
local util = require("util")

local M = {}

-- A tunnel counts as usable while its last handshake is younger than this.
M.HANDSHAKE_MAX_AGE = 180

-- Multi-site operation: parker-sites probes each site every second. When no
-- site is up, our tunnels may still have a recent handshake, but they do
-- not route. Only trust a status that parker-sites has written recently.
M.SITES_STATUS = "/tmp/parker-sites/status"
M.SITES_STATUS_MAX_AGE = 30

function M.handshake_ages(wg, now)
	-- { iface = age } of the wg-interfaces with exactly one peer.
	local result = {}
	for iface, data in pairs(wg) do
		if util.tablelength(data.peers) == 1 then
			for _, peer in pairs(data.peers) do
				result[iface] = now - peer.latest_handshake
			end
		end
	end
	return result
end

function M.usable(wg, now, ages)
	-- The tunnels with a recent handshake, sorted by name.
	ages = ages or M.handshake_ages(wg, now)
	local result = {}
	for iface, age in pairs(ages) do
		if age < M.HANDSHAKE_MAX_AGE then
			table.insert(result, iface)
		end
	end
	table.sort(result)
	return result
end

function M.no_site_up(now)
	local st = stat.stat(M.SITES_STATUS)
	if not st or now - st.st_mtime > M.SITES_STATUS_MAX_AGE then
		return false
	end
	return (util.read_file(M.SITES_STATUS) or ""):find("\nactive=nil\n", 1, true) ~= nil
end

function M.active(wg, now, ages)
	-- The tunnels noderoute may route through, and whether that list is
	-- empty only because parker-sites has found no site up.
	local result = M.usable(wg, now, ages)
	if #result > 0 and M.no_site_up(now) then
		return {}, true
	end
	return result, false
end

function M.key(wg, now)
	-- A string that changes when the result of active() may change.
	-- noderoute.sh polls it while noderoute.lua sleeps.
	wg = wg or util.get_wg_info()
	now = now or os.time()
	local key = ""
	for _, iface in ipairs(M.usable(wg, now)) do
		key = key .. iface .. " "
	end
	if M.no_site_up(now) then
		key = key .. "no-site-up"
	end
	return key
end

return M

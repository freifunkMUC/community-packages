-- Test of respondd_json() in parker-sites.lua: the gateway fields of the
-- active site.
-- luacheck: globals loadstring
-- Run: lua5.1 tests/respondd-gateway-test.lua (from the package directory).

package.preload["jsonc"] = function() return { stringify = function(t) return t end } end
package.preload["posix"] = function() return {} end
package.preload["util"] = function() return {} end

-- parker-sites.lua runs its daemon loop at the end. Load only the
-- functions before it and return respondd_json.
local f = assert(io.open("luasrc/usr/share/lua/parker-sites.lua"))
local src = f:read("*a")
f:close()
local cut = assert(src:find('\nif arg[1] == "pin" then', 1, true))
local load_chunk = loadstring or load
local respondd_json = assert(load_chunk(src:sub(1, cut) .. "return respondd_json"))()

local failed = 0
local function check(name, got, want)
	local ok = got == want
	print((ok and "PASS " or "FAIL ") .. name .. (ok and "" or (": got " .. tostring(got))))
	if not ok then failed = failed + 1 end
end

local conf = { sites = {
	muc01 = { pgws = {
		{ name = "pgw01", address6 = "fe80::1" },
		{ name = "pgw02", address6 = "fe80::2" },
	} },
	vie01 = { pgws = { { name = "pgw03" } } },
} }
local names = { "muc01", "vie01" }
local iface = { muc01 = "wg_muc01", vie01 = "wg_vie01" }
local db = { sites = {
	muc01 = { state = "up", since = 100, pgw = "pgw02" },
	vie01 = { state = "up", since = 100, pgw = "pgw03" },
} }

-- Active pgw with an IPv6 address: gateway is the same address as gateway6.
local ret = respondd_json(conf, names, db, iface, "muc01", 160)
check("address6: gateway", ret.gateway, "fe80::2")
check("address6: gateway6", ret.gateway6, "fe80::2")
check("address6: gateway_nexthop", ret.gateway_nexthop, "wg_muc01")
check("address6: active", ret.mesh_vpn.groups.muc01.peers.pgw02.method, "active")
check("address6: standby", ret.mesh_vpn.groups.vie01.peers.pgw03.method, "standby")

-- Active pgw without an IPv6 address: gateway is "name (site)".
ret = respondd_json(conf, names, db, iface, "vie01", 160)
check("no address6: gateway", ret.gateway, "pgw03 (vie01)")
check("no address6: gateway6", ret.gateway6, nil)

-- No active site: no gateway fields.
ret = respondd_json(conf, names, db, iface, nil, 160)
check("no active site: gateway", ret.gateway, nil)

os.exit(failed == 0 and 0 or 1)

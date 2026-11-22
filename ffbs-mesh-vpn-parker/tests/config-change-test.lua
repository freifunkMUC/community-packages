-- Test of same_config() in nodeconfig.lua: a new config replaces
-- noderoute.json only when its content changed.
-- luacheck: globals loadstring
-- Run: lua5.1 tests/config-change-test.lua (from the package directory).

-- read_file(path) returns path, json.parse(path) returns files[path].
local files = {}
package.preload["jsonc"] = function()
	return { parse = function(s) return files[s] end }
end
package.preload["util"] = function()
	return {
		read_file = function(path) if files[path] ~= nil then return path end end,
		log = function() end,
	}
end
package.preload["simple-uci"] = function() return { cursor = function() return {} end } end

local load_chunk = loadstring or load
local function load_until(path, marker, name)
	local f = assert(io.open(path))
	local src = f:read("*a")
	f:close()
	local cut = assert(src:find(marker, 1, true))
	return assert(load_chunk(src:sub(1, cut) .. "return " .. name))()
end
local same_config = load_until("luasrc/usr/share/lua/nodeconfig.lua", '\nutil.log("Starting up")', "same_config")

local failed = 0
local function check(name, got, want)
	local ok = got == want
	print((ok and "PASS " or "FAIL ") .. name .. (ok and "" or (": got " .. tostring(got))))
	if not ok then failed = failed + 1 end
end

local function config(nonce, time, pubkey)
	return {
		nonce = nonce, time = time, id = 7, mtu = 1420,
		concentrators = { { id = 3, pubkey = pubkey, endpoint = "[2001:db8::12]:40000" } },
		sites = { vie01 = { concentrator = 3, pgws = { { name = "pgw03" }, { name = "pgw04" } } } },
	}
end

-- same_config
local function same(old, new)
	files["/new.json"] = new
	return same_config(old, "/new.json")
end
files["/old.json"] = config("a", 100, "K4")
check("only nonce and time changed", same("/old.json", config("b", 220, "K4")), true)
check("concentrator changed", same("/old.json", config("b", 220, "K3")), false)
local extra = config("b", 220, "K4")
extra.primary_site = "muc01"
check("key added", same("/old.json", extra), false)
local less = config("b", 220, "K4")
less.mtu = nil
check("key removed", same("/old.json", less), false)
local flipped = config("b", 220, "K4")
flipped.sites.vie01.pgws[2].preferred = true
check("only preferred pgw changed", same("/old.json", flipped), true)
check("no old file", same("/missing.json", config("b", 220, "K4")), false)
check("no new file", same_config("/old.json", "/missing.json"), false)

if failed > 0 then
	os.exit(1)
end

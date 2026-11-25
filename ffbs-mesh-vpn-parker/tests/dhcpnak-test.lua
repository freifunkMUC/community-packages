-- Tests parker/dhcpnak.lua: the conflict check runs only for a shared address.
-- Run in the package directory: lua tests/dhcpnak-test.lua

package.path = "luasrc/usr/share/lua/?.lua;" .. package.path

local files, claims, calls = {}, {}, 0
package.preload["util"] = function()
	return {
		log = function() end,
		read_file = function(p) return files[p] end,
		write_file = function(p, c) files[p] = c end,
	}
end
package.preload["clientaddr"] = function()
	return {
		claim = function(addr)
			calls = calls + 1
			return claims[addr]
		end,
	}
end
os.execute = function() return 0 end -- luacheck: ignore
os.remove = function(p) files[p] = nil end -- luacheck: ignore
io.popen = function() -- luacheck: ignore
	return { lines = function() return function() end end, close = function() end }
end

local dhcpnak = require("parker.dhcpnak")
local STATE = "/tmp/parker-dhcp-nak"

local failed = 0
local function check(name, ok)
	print((ok and "PASS " or "FAIL ") .. name)
	if not ok then failed = failed + 1 end
end

claims["10.0.0.1"] = "02:00:00:00:00:02"

check("own address: hold although another node has it", dhcpnak.start("10.0.0.1/24", false) and calls == 0)
dhcpnak.expire()
check("own address: expire keeps the hold", files[STATE] ~= nil and calls == 0)
dhcpnak.stop()

check("shared address: no hold when another node has it", not dhcpnak.start("10.0.0.1/24", true) and calls == 1)

claims["10.0.0.1"] = nil
check("shared address: hold when free", dhcpnak.start("10.0.0.1/24", true))
claims["10.0.0.1"] = "02:00:00:00:00:02"
dhcpnak.expire()
check("shared address: expire stops the hold on a claim", files[STATE] == nil)

files[STATE] = "10.0.0.1 " .. (os.time() - dhcpnak.HOLD)
dhcpnak.expire()
check("hold ends after HOLD", files[STATE] == nil)

if failed > 0 then
	os.exit(1)
end

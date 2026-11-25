-- Test of dhcp.captive_portal_url() and option 114 in the client options.
-- Run: lua5.1 tests/captive-portal-test.lua (from the package directory).

package.path = "luasrc/usr/share/lua/?.lua;" .. package.path

local dhcp = require("parker.dhcp")

local failed = 0
local function check(name, got, want)
	if got ~= want then
		print("FAIL " .. name .. ": got " .. tostring(got) .. ", want " .. tostring(want))
		failed = failed + 1
	end
end

local URL = "https://freifunk-dillingen-donau.de/captive"
check("valid", dhcp.captive_portal_url(URL), URL)
check("query", dhcp.captive_portal_url("https://x.example/c?a=1&b=%20"), "https://x.example/c?a=1&b=%20")
check("nil", dhcp.captive_portal_url(nil), nil)
check("not a string", dhcp.captive_portal_url(5), nil)
check("empty", dhcp.captive_portal_url(""), nil)
check("http", dhcp.captive_portal_url("http://x.example/captive"), nil)
check("urn", dhcp.captive_portal_url("urn:ietf:params:capport:unrestricted"), nil)
check("comma", dhcp.captive_portal_url("https://x.example/a,b"), nil)
check("space", dhcp.captive_portal_url("https://x.example/a b"), nil)
check("quote", dhcp.captive_portal_url('https://x.example/a"b'), nil)
check("newline", dhcp.captive_portal_url("https://x.example/a\nb"), nil)
check("hash", dhcp.captive_portal_url("https://x.example/a#b"), nil)
check("255 bytes", dhcp.captive_portal_url("https://" .. string.rep("a", 247)) ~= nil, true)
check("256 bytes", dhcp.captive_portal_url("https://" .. string.rep("a", 248)), nil)

-- Option 114 is added next to the other options and removed without a URL.
local options = dhcp.merge_option({ "option:mtu,1280" }, "114", { URL })
check("add", table.concat(options, " "), "option:mtu,1280 114," .. URL)
options = dhcp.merge_option(options, "114", { nil })
check("remove", table.concat(options, " "), "option:mtu,1280")
check("unchanged", dhcp.merge_option(options, "114", { nil }), nil)

if failed > 0 then
	os.exit(1)
end
print("ok")

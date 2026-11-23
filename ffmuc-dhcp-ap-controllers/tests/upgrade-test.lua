-- Tests the upgrade script with mock site and uci modules.
-- Run in the package directory: lua tests/upgrade-test.lua

local SCRIPT = "luasrc/lib/gluon/upgrade/998-ffmuc-dhcp-ap-controllers"

local SITE, DHCP

local function site_value(path)
	return function(default)
		local v = SITE
		for _, k in ipairs(path) do
			v = type(v) == "table" and v[k] or nil
		end
		if v == nil then
			return default
		end
		return v
	end
end

package.preload["gluon.site"] = function()
	return setmetatable({}, {
		__index = function(_, a)
			return setmetatable({}, {
				__index = function(_, b)
					return site_value({ a, b })
				end,
			})
		end,
	})
end

package.preload["simple-uci"] = function()
	local cursor = {}
	function cursor:get(_, s, o)
		if DHCP[s] == nil then return nil end
		if o == nil then return DHCP[s][".type"] end
		return DHCP[s][o]
	end
	function cursor:get_list(_, s, o)
		local v = DHCP[s] and DHCP[s][o]
		if type(v) == "string" then return { v } end
		return v or {}
	end
	function cursor:set(_, s, o, v) DHCP[s][o] = v end
	function cursor:section(_, t, s, values)
		DHCP[s] = { [".type"] = t }
		for k, v in pairs(values or {}) do DHCP[s][k] = v end
	end
	function cursor:delete(_, s, o)
		if o == nil then DHCP[s] = nil elseif DHCP[s] then DHCP[s][o] = nil end
	end
	function cursor:commit() end
	return { cursor = function() return cursor end }
end

local failed = 0
local function check(name, ok)
	print((ok and "PASS " or "FAIL ") .. name)
	if not ok then failed = failed + 1 end
end

local function run(site, dhcp)
	SITE, DHCP = site, dhcp
	assert(loadfile(SCRIPT))()
	return DHCP
end

local d = run({ dhcp_ap_controllers = { unifi4 = "198.51.100.10", omada4 = { "198.51.100.11", "300.1.1.1" } } }, {
	client = { [".type"] = "dhcp", dhcp_option = { "option:ntp-server,192.0.2.1", "138,192.0.2.9" } },
	parker_unifi = { [".type"] = "vendorclass" },
})
check("unifi: vendorclass section", d.unifi_controller and d.unifi_controller.vendorclass == "ubnt"
	and d.unifi_controller.dhcp_option[1] == "vendor:ubnt,1,198.51.100.10")
check("old parker section removed", d.parker_unifi == nil)
check("omada: own entry replaced, invalid address dropped, others kept",
	table.concat(d.client.dhcp_option, " ") == "option:ntp-server,192.0.2.1 138,198.51.100.11")

d = run({}, {
	client = { [".type"] = "dhcp", dhcp_option = { "138,192.0.2.9" } },
	unifi_controller = { [".type"] = "vendorclass" },
})
check("unset: unifi section removed", d.unifi_controller == nil)
check("unset: omada entry removed", d.client.dhcp_option == nil)

d = run({ dhcp_ap_controllers = { omada4 = { "198.51.100.11" } } }, {})
check("no client section: created", d.client and d.client.dhcp_option[1] == "138,198.51.100.11")

if failed > 0 then
	os.exit(1)
end

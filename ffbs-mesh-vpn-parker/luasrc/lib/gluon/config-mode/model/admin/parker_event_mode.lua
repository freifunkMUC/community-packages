local limits = require("parker.limits")
local uci = require("simple-uci").cursor()

local f = Form(translate("Event mode"))

local s = f:section(Section, nil, translate("ffbs-mesh-vpn-parker:event-mode:description"))

if not limits.available(limits.mem_total()) then
	f:section(Section, nil, translate("ffbs-mesh-vpn-parker:event-mode:no-ram"))
	return f
end

local enabled = s:option(Flag, "enabled", translate("Enable event mode"))
enabled.default = uci:get_bool("parker", "event_mode", "enabled", false)

function f:write()
	uci:section("parker", "event_mode", "event_mode", { enabled = enabled.data })
	uci:commit("parker")
end

return f

-- Test of noderoute.lua and parker/tunnels.lua with a mock node: which
-- tunnels are usable, what a cycle does, and what it logs.
-- luacheck: globals loadstring arg
-- Run: lua5.1 tests/noderoute-test.lua (from the package directory).
-- With a path, it prints the actions of all scenarios for that copy of
-- noderoute.lua instead, to compare two versions of it:
--   lua5.1 tests/noderoute-test.lua old-noderoute.lua > old.txt

package.path = "luasrc/usr/share/lua/?.lua;" .. package.path
local SRC = arg and arg[1] or "luasrc/usr/share/lua/noderoute.lua"
local TRACE = arg and arg[1] ~= nil
local load_chunk = loadstring or load

-- The mock node -------------------------------------------------------

local W -- the world of the current scenario
local now = 100000

local function new_world()
	return {
		fs = {},
		mtime = {},
		uci = {
			dhcp = { dnsmasq0 = { [".type"] = "dnsmasq" } },
			network = { client = { [".type"] = "interface", proto = "dhcp" } },
			parker = {},
		},
		changes = {},
		routes4 = "",
		ebt = {},
		running = {},
		wg = {},
		actions = {},
		logs = {},
	}
end

local function act(s)
	table.insert(W.actions, s)
end

local function ser(v)
	if type(v) == "table" then
		local keys = {}
		for k in pairs(v) do
			table.insert(keys, k)
		end
		table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
		local parts = {}
		for _, k in ipairs(keys) do
			table.insert(parts, tostring(k) .. "=" .. ser(v[k]))
		end
		return "{" .. table.concat(parts, ",") .. "}"
	end
	return tostring(v)
end

local CONFIGS = {}
package.preload["jsonc"] = function()
	return {
		stringify = ser,
		parse = function(s)
			if s == "STATUS" then
				local c = W.uci.network.client
				local addrs = {}
				if c.ipaddr then
					table.insert(addrs, { address = c.ipaddr:match("^[^/]+") })
				end
				return { proto = c.proto, up = true, ["ipv4-address"] = addrs }
			end
			return CONFIGS[s]
		end,
	}
end

package.preload["posix"] = function() return {} end
package.preload["posix.sys.stat"] = function()
	return {
		stat = function(p)
			if W.fs[p] == nil then return nil end
			return { st_mtime = W.mtime[p] or now }
		end,
	}
end

local function uci_value(v)
	if type(v) == "table" then
		local t = {}
		for i, x in ipairs(v) do t[i] = tostring(x) end
		return t
	end
	return v ~= nil and tostring(v) or nil
end

package.preload["uci"] = function()
	local uci = {}
	function uci.get(c, s, o)
		local sec = W.uci[c] and W.uci[c][s]
		if sec == nil then return nil end
		if o == nil then return sec[".type"] end
		return sec[o]
	end
	function uci.set(c, s, o, v)
		W.uci[c] = W.uci[c] or {}
		if v == nil then
			if W.uci[c][s] == nil then
				W.uci[c][s] = { [".type"] = o }
				table.insert(W.changes, { c, "add " .. s })
				act("uci add " .. c .. "." .. s .. "=" .. o)
			end
			return true
		end
		v = uci_value(v)
		W.uci[c][s] = W.uci[c][s] or {}
		if ser(W.uci[c][s][o]) ~= ser(v) then
			W.uci[c][s][o] = v
			table.insert(W.changes, { c, "set " .. s .. "." .. o })
			act("uci set " .. c .. "." .. s .. "." .. o .. "=" .. ser(v))
		end
		return true
	end
	function uci.delete(c, s, o)
		local sec = W.uci[c] and W.uci[c][s]
		if sec ~= nil and sec[o] ~= nil then
			sec[o] = nil
			table.insert(W.changes, { c, "delete " .. s .. "." .. o })
			act("uci delete " .. c .. "." .. s .. "." .. o)
		end
		return true
	end
	function uci.changes(c)
		local r = {}
		for _, ch in ipairs(W.changes) do
			if c == nil or ch[1] == c then
				table.insert(r, ch[1] .. ": " .. ch[2])
			end
		end
		return r
	end
	function uci.commit(c)
		local keep = {}
		for _, ch in ipairs(W.changes) do
			if ch[1] ~= c then table.insert(keep, ch) end
		end
		W.changes = keep
		act("uci commit " .. c)
		return true
	end
	function uci.foreach(c, t, fn)
		for name, sec in pairs(W.uci[c] or {}) do
			if sec[".type"] == t then
				local copy = { [".name"] = name }
				if fn(copy) == false then return end
			end
		end
	end
	return uci
end

package.preload["clientaddr"] = function()
	return { RESERVED = 16, select = function(conf) return W.address4 or conf.address4 end }
end
package.preload["parker.dhcpnak"] = function()
	return {
		stop = function() act("dhcpnak.stop") end,
		start = function(cidr) act("dhcpnak.start " .. tostring(cidr)) end,
		expire = function() end,
	}
end
package.preload["parker.ragoodbye"] = function()
	return {
		cancel = function() act("ragoodbye.cancel") end,
		send = function() act("ragoodbye.send") end,
	}
end

local util = require("util")
util.read_file = function(p) return W.fs[p] end
util.write_file = function(p, d)
	act("write " .. p .. " " .. tostring(d))
	W.fs[p] = d
	return true
end
util.log = function(s) table.insert(W.logs, tostring(s)) end
util.sleep = function() end
util.shuffle = function(t) table.sort(t) return t end
util.check_output = function(cmd)
	if cmd == "wg show all dump" then
		local lines = {}
		local ifaces = {}
		for iface in pairs(W.wg) do table.insert(ifaces, iface) end
		table.sort(ifaces)
		for _, iface in ipairs(ifaces) do
			table.insert(lines, iface .. " priv pub 0 off")
			for i, hs in ipairs(W.wg[iface]) do
				table.insert(lines, iface .. " peer" .. i .. " (none) [::1]:1 ::/0 " .. hs .. " 0 0 25")
			end
		end
		return table.concat(lines, "\n")
	end
	if cmd:find("^ip r show proto") or cmd == "ip -4 r show" then
		return W.routes4
	end
	if cmd == "ip -6 r show" then return "" end
	local chain = cmd:match("^ebtables%-tiny %-L (%S+)")
	if chain then return W.ebt[chain] and "-j DROP" or "" end
	if cmd:find("^ubus call network.interface") then return "STATUS" end
	return ""
end

local limits = require("parker.limits")
limits.mem_total = function() return 262144 end
limits.apply_sysctl = function() return false end

os.time = function() return now end -- luacheck: ignore
os.remove = function(p) -- luacheck: ignore
	act("remove " .. p)
	W.fs[p] = nil
end
os.execute = function(cmd) -- luacheck: ignore
	act("exec " .. cmd)
	local svc = cmd:match("^(%S+) running")
	if svc then return W.running[svc] and 0 or 1 end
	local f = cmd:match("^rm (%S+) %-f$")
	if f then W.fs[f] = nil end
	f = cmd:match("^touch (%S+)$")
	if f then W.fs[f] = "" end
	local chain = cmd:match("^ebtables%-tiny %-A (%S+)")
	if chain then W.ebt[chain] = true end
	chain = cmd:match("^ebtables%-tiny %-F (%S+)")
	if chain then W.ebt[chain] = nil end
	local r = cmd:match("^ip %-4 r replace (default via %S+ dev %S+ proto %d+)")
	if r then W.routes4 = r end
	if cmd:find("^ip %-4 r del default") then W.routes4 = "" end
	return 0
end

-- Each cycle runs all of noderoute.lua, as a new lua process on the node does.
local TMP = "/tmp/ff"
local REPORT = {}
local real_open = io.open
io.open = function(p, mode) -- luacheck: ignore
	if p == "/tmp/nodeconfig-report.tmp" then
		REPORT.text = nil
		return { write = function(_, s) REPORT.text = s end, close = function() end }
	end
	return real_open(p, mode)
end
local f = assert(real_open(SRC))
local noderoute = assert(load_chunk(f:read("*a"), "noderoute.lua"))
f:close()

-- Scenarios -------------------------------------------------------------

local CONF = {
	address4 = "10.0.0.1", address6 = "2001:db8::1", range4 = "10.0.0.0/24", range6 = "2001:db8::/64",
	concentrators = {
		{ id = 1, address4 = "10.255.0.1", address6 = "fe80::1" },
		{ id = 2, address4 = "10.255.0.2", address6 = "fe80::2" },
	},
}
local XLAT = setmetatable({ xlat_range6 = "2001:db8:64::/96" }, { __index = CONF })
CONFIGS["CONF"] = CONF
CONFIGS["XLAT"] = XLAT

local function world(conf, wg)
	W = new_world()
	W.fs[TMP .. "/noderoute.json"] = conf
	W.wg = wg
	W.fs["/sys/class/net/wg_1/mtu"] = "1420"
	W.fs["/sys/class/net/wg_2/mtu"] = "1400"
end

local function cycle()
	W.actions, W.logs = {}, {}
	arg = { TMP } -- luacheck: ignore
	noderoute()
	now = now + 30
	return { actions = W.actions, logs = W.logs, report = REPORT.text }
end

local scenarios = {}
local function scenario(name, fn) table.insert(scenarios, { name = name, fn = fn }) end

scenario("boot, two tunnels, then steady", function()
	world("CONF", { wg_1 = { now - 5 }, wg_2 = { now - 7 } })
	return { cycle(), cycle(), cycle() }
end)
scenario("selected tunnel goes stale", function()
	world("XLAT", { wg_1 = { now - 5 }, wg_2 = { now - 7 } })
	local c1 = cycle()
	W.wg.wg_1 = { now - 200 }
	W.wg.wg_2 = { now }
	return { c1, cycle(), cycle() }
end)
scenario("all tunnels go down, then steady", function()
	world("XLAT", { wg_1 = { now - 5 } })
	local c1 = cycle()
	W.wg.wg_1 = { 0 }
	return { c1, cycle(), cycle() }
end)
scenario("no site up", function()
	world("CONF", { wg_1 = { now - 5 } })
	local c1 = cycle()
	W.fs["/tmp/parker-sites/status"] = "x=1\nactive=nil\ny=2\n"
	W.mtime["/tmp/parker-sites/status"] = now
	local c2 = cycle()
	local c3 = cycle()
	W.mtime["/tmp/parker-sites/status"] = now - 31
	return { c1, c2, c3, cycle() }
end)
scenario("other radvd running", function()
	world("CONF", { wg_1 = { now - 5 } })
	local c1 = cycle()
	W.running["/etc/init.d/parker-radvd"] = true
	return { c1, cycle() }
end)
scenario("dirty uci", function()
	world("CONF", { wg_1 = { now - 5 } })
	table.insert(W.changes, { "network", "set x" })
	return { cycle(), cycle() }
end)
scenario("active without config", function()
	world(nil, { wg_1 = { now - 5 } })
	return { cycle() }
end)
scenario("no tunnels at boot", function()
	world("CONF", { wg_1 = { 0 }, wg_2 = { now - 500 } })
	return { cycle(), cycle() }
end)
scenario("tunnel MTU changes, client address moves", function()
	world("XLAT", { wg_1 = { now - 5 } })
	local c1 = cycle()
	W.fs["/sys/class/net/wg_1/mtu"] = "1380"
	local c2 = cycle()
	W.address4 = "10.0.0.20"
	return { c1, c2, cycle(), cycle() }
end)

if TRACE then
	for _, s in ipairs(scenarios) do
		for i, c in ipairs(s.fn()) do
			print("## " .. s.name .. " / cycle " .. i .. ": " .. tostring(c.report))
			for _, a in ipairs(c.actions) do
				-- The log state record of the new version is no action on the network.
				if not a:find("noderoute%-state") then print(a) end
			end
		end
	end
	os.exit(0)
end

-- Checks ----------------------------------------------------------------

local failed = 0
local function check(name, ok, got)
	print((ok and "PASS " or "FAIL ") .. name .. (ok and "" or (": got " .. ser(got))))
	if not ok then failed = failed + 1 end
end
local function has(logs, pattern)
	for _, l in ipairs(logs) do
		if l:find(pattern) then return true end
	end
	return false
end
local function run(name)
	for _, s in ipairs(scenarios) do
		if s.name == name then return s.fn() end
	end
end

-- parker/tunnels.lua
local tunnels = require("parker.tunnels")
local function wg(t)
	local r = {}
	for iface, peers in pairs(t) do
		r[iface] = { peers = {} }
		for i, hs in ipairs(peers) do r[iface].peers["p" .. i] = { latest_handshake = hs } end
	end
	return r
end
W = new_world()
local u = tunnels.usable(wg({
	wg_3 = { now - 179 }, wg_1 = { now - 1 }, wg_2 = { now - 180 }, wg_4 = { 0 }, wg_5 = { now, now },
}), now)
check("usable: age < 180, one peer, sorted", ser(u) == "{1=wg_1,2=wg_3}", u)
check("no status file: a site is up", tunnels.no_site_up(now) == false)
W.fs[tunnels.SITES_STATUS] = "a=1\nactive=nil\n"
W.mtime[tunnels.SITES_STATUS] = now - 30
check("fresh active=nil: no site up", tunnels.no_site_up(now) == true)
W.mtime[tunnels.SITES_STATUS] = now - 31
check("stale active=nil: ignored", tunnels.no_site_up(now) == false)
W.fs[tunnels.SITES_STATUS] = "a=1\nactive=muc01\n"
W.mtime[tunnels.SITES_STATUS] = now
check("active site: a site is up", tunnels.no_site_up(now) == false)
W.fs[tunnels.SITES_STATUS] = "a=1\nactive=nil\n"
local sel, none = tunnels.active(wg({ wg_1 = { now } }), now)
check("active: no site up empties the list", #sel == 0 and none == true, sel)
check("key: tunnels and no-site-up", tunnels.key(wg({ wg_2 = { now }, wg_1 = { now } }), now) == "wg_1 wg_2 no-site-up")
W.fs[tunnels.SITES_STATUS] = nil
check("key: tunnels only", tunnels.key(wg({ wg_1 = { now } }), now) == "wg_1 ")
check("key: nothing", tunnels.key(wg({ wg_1 = { 0 } }), now) == "")

-- What a cycle logs.
local c = run("boot, two tunnels, then steady")
check("boot: state line", has(c[1].logs, "^state: routing active"), c[1].logs)
check("boot: state names the tunnels and the route",
	has(c[1].logs, "tunnels wg_1 %(5s%) wg_2 %(7s%), route via wg_1"), c[1].logs)
check("boot: state names the client addresses and leases",
	has(c[1].logs, "client 10%.0%.0%.1/24 2001:db8::1/64, up to %d+ leases"), c[1].logs)
check("boot: route activation is logged", has(c[1].logs, "^Route activated"), c[1].logs)
check("steady: no log", #c[2].logs == 0 and #c[3].logs == 0, c[2].logs)
check("steady: report", c[3].report == "active (idle) via wg_1")

c = run("selected tunnel goes stale")
check("stale: transition logged", has(c[2].logs, "inactive tunnel") and has(c[2].logs, "activating route for wg_2"), c[2].logs)
check("stale: new state logged", has(c[2].logs, "^state: .*tunnels wg_2 %(0s%), route via wg_2"), c[2].logs)
check("stale: xlat in state", has(c[2].logs, "xlat 2001:db8:64::/96"), c[2].logs)
check("stale: then quiet", #c[3].logs == 0, c[3].logs)

c = run("all tunnels go down, then steady")
check("down: inactive state logged", has(c[2].logs, "^state: routing inactive, no usable tunnels$"), c[2].logs)
check("down: route removal logged", has(c[2].logs, "Removing default routes"), c[2].logs)
check("down: then quiet", #c[3].logs == 0, c[3].logs)

c = run("no site up")
check("no site: then quiet", #c[3].logs == 0, c[3].logs)
check("no site: state", has(c[2].logs, "^state: routing inactive, no site up$"), c[2].logs)
check("stale status: back to active", has(c[4].logs, "^state: routing active"), c[4].logs)

c = run("dirty uci")
check("dirty: logged each cycle", has(c[1].logs, "UCI is dirty") and has(c[2].logs, "UCI is dirty"), c[2].logs)

c = run("active without config")
check("no config: logged", has(c[1].logs, "no config present"), c[1].logs)

c = run("other radvd running")
check("other radvd: stop logged", has(c[2].logs, "^Stopping /etc/init.d/parker%-radvd"), c[2].logs)

c = run("tunnel MTU changes, client address moves")
check("mtu: route MTU change logged", has(c[2].logs, "^Setting the IPv4 MTU of the route via wg_1 to 1352"), c[2].logs)
check("mtu: state unchanged, no state line", not has(c[2].logs, "^state:"), c[2].logs)
check("move: new client address in state", has(c[3].logs, "^state: .*client 10%.0%.0%.20/24.*up to 238 leases"), c[3].logs)
check("move: then quiet", #c[4].logs == 0, c[4].logs)

if failed > 0 then
	os.exit(1)
end

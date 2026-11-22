-- Test of the pgw switch guard and the switch report (parker/switchguard.lua
-- and guard_config(), report_result() and health() in parker-sites.lua).
-- luacheck: globals loadstring
-- Run: lua5.1 tests/switch-guard-test.lua (from the package directory).

package.path = "luasrc/usr/share/lua/?.lua;" .. package.path

-- A file system in memory. jsonc stores Lua tables as Lua source.
local fs, execs, logs = {}, {}, {}
local function ser(v)
	if type(v) == "table" then
		local parts = {}
		for k, x in pairs(v) do
			table.insert(parts, "[" .. ser(k) .. "]=" .. ser(x))
		end
		return "{" .. table.concat(parts, ",") .. "}"
	end
	return type(v) == "string" and string.format("%q", v) or tostring(v)
end
local load_chunk = loadstring or load
package.preload["jsonc"] = function()
	return {
		stringify = ser,
		parse = function(s)
			local fn = s:match("^{") and load_chunk("return " .. s)
			return fn and fn() or nil
		end,
	}
end
package.preload["posix"] = function() return {} end
local wg_out = ""
package.preload["util"] = function()
	return {
		read_file = function(p) return fs[p] end,
		write_file = function(p, d) fs[p] = d end,
		log = function(m) table.insert(logs, m) end,
		check_output = function(cmd)
			if cmd:find("resolve") then return "[2001:db8::3]:40000" end
			if cmd:find("config_server") then return "broker.example" end
			if cmd:find("public%-key") then return "nodekey=" end
			if cmd:find("peers") then return wg_out end
			return ""
		end,
	}
end

local now = 1000
os.time = function() return now end -- luacheck: ignore
os.remove = function(p) fs[p] = nil end -- luacheck: ignore
os.execute = function(cmd) table.insert(execs, cmd) return 0 end -- luacheck: ignore

local f = assert(io.open("luasrc/usr/share/lua/parker-sites.lua"))
local src = f:read("*a")
f:close()
local cut = assert(src:find('\nif arg[1] == "guard" then', 1, true))
local ps = assert(load_chunk(src:sub(1, cut)
	.. "return { guard = guard_config, result = report_result, health = health, T = T }"))()
local sg = require("parker.switchguard")
local json = require("jsonc")
local T = ps.T

local failed = 0
local function check(name, got, want)
	local ok = got == want
	print((ok and "PASS " or "FAIL ") .. name .. (ok and "" or (": got " .. tostring(got))))
	if not ok then failed = failed + 1 end
end

local STATE, CONFIG = "/tmp/parker-sites", "/tmp/config.json"
local P3 = { name = "pgw03", pubkey = "K3", endpoint = "pgw03:40000", address6 = "fe80::3" }
local P4 = { name = "pgw04", pubkey = "K4", endpoint = "pgw04:40000", address6 = "fe80::4" }
local P5 = { name = "pgw05", pubkey = "K5", endpoint = "pgw05:40000", address6 = "fe80::5" }
local function config(pgw)
	return {
		primary_site = "vie01",
		sites = { vie01 = { concentrator = 3, pgws = { P3, P4, P5 } } },
		concentrators = { { id = 3, pubkey = pgw.pubkey, endpoint = pgw.endpoint, address6 = pgw.address6 } },
	}
end
local function fetched(pgw)
	fs[CONFIG] = json.stringify(config(pgw))
	ps.guard(CONFIG)
	return json.parse(fs[CONFIG]).concentrators[1].pubkey
end
local function record(rec)
	fs[STATE .. "/switch.vie01"] = rec and json.stringify(rec) or nil
end

-- switchguard.decide
local site = config(P3).sites.vie01
local rec = { from = "pgw03", to = "pgw04", since = 1000 }
check("decide: left pgw in hold", sg.decide(rec, site, { pubkey = "K3" }, 1100, T), "keep")
check("decide: new pgw", sg.decide(rec, site, { pubkey = "K4" }, 1100, T), "match")
check("decide: third pgw", sg.decide(rec, site, { pubkey = "K5" }, 1100, T), "expire")
check("decide: unconfirmed after hold", sg.decide(rec, site, { pubkey = "K3" }, 1000 + T.switch_hold, T), "keep")
check("decide: unconfirmed until guard max",
	sg.decide(rec, site, { pubkey = "K3" }, 1000 + T.switch_guard_max, T), "expire")
rec.confirmed = 1010
check("decide: confirmed in hold", sg.decide(rec, site, { pubkey = "K3" }, 1000 + T.switch_hold - 1, T), "keep")
check("decide: confirmed after hold", sg.decide(rec, site, { pubkey = "K3" }, 1000 + T.switch_hold, T), "expire")
check("decide: clock back", sg.decide(rec, site, { pubkey = "K3" }, 900, T), "expire")
check("decide: new pgw not in site",
	sg.decide({ from = "pgw03", to = "pgw09", since = 1000 }, site, { pubkey = "K3" }, 1100, T), "expire")

-- switchguard.retry_after and chosen
check("backoff 1", sg.retry_after(1, T), 3)
check("backoff 3", sg.retry_after(3, T), 12)
check("backoff max", sg.retry_after(10, T), 60)
check("chosen", sg.chosen('{"Message":"OK","site":"vie01","pgw":"pgw04","hold":900}'), "pgw04")
check("chosen: old broker", sg.chosen('{"Message":"OK"}'), nil)

-- guard_config: no record, the config stays.
record(nil)
now = 1000
check("guard: no record", fetched(P3), "K3")
local before = fs[CONFIG]
ps.guard(CONFIG)
check("guard: no write without change", fs[CONFIG], before)

-- A switch pgw03 -> pgw04 at 1000: the broker still names pgw03.
record({ from = "pgw03", to = "pgw04", since = 1000 })
now = 1100
check("guard: flip-back blocked", fetched(P3), "K4")
check("guard: endpoint of new pgw", json.parse(fs[CONFIG]).concentrators[1].endpoint, "pgw04:40000")
check("guard: record kept", fs[STATE .. "/switch.vie01"] ~= nil, true)
check("guard: broker names new pgw", fetched(P4), "K4")
-- Drain/rebalance to a third pgw: applied, record removed.
check("guard: third pgw applied", fetched(P5), "K5")
check("guard: record removed", fs[STATE .. "/switch.vie01"], nil)

-- Unconfirmed: the guard holds after switch_hold, until switch_guard_max.
record({ from = "pgw03", to = "pgw04", since = 1000 })
now = 1000 + T.switch_hold + 10
check("guard: unconfirmed holds after hold", fetched(P3), "K4")
now = 1000 + T.switch_guard_max
check("guard: unconfirmed expires", fetched(P3), "K3")
check("guard: expired record removed", fs[STATE .. "/switch.vie01"], nil)

-- Confirmed: after switch_hold the broker answer is applied.
record({ from = "pgw03", to = "pgw04", since = 1000, confirmed = 1005 })
now = 1000 + T.switch_hold
check("guard: confirmed, broker moves back", fetched(P3), "K3")

-- report_result
local RF = STATE .. "/report.vie01"
fs[RF] = nil
check("result: none yet", ps.result("vie01", "pgw04"), nil)
fs[RF] = 'rc 0\n{"Message":"OK","site":"vie01","pgw":"pgw04","hold":900}'
check("result: 200 with pgw", ps.result("vie01", "pgw04"), "confirmed")
fs[RF] = 'rc 0\n{"Message":"OK"}'
check("result: 200 without pgw", ps.result("vie01", "pgw04"), "confirmed")
fs[RF] = 'rc 0\n{"Message":"OK","pgw":"pgw03"}'
check("result: 200 other pgw", ps.result("vie01", "pgw04"), "retry")
fs[RF] = "rc 8\nDownloading 'http://b/api/v3/switch'\nConnecting to b\nHTTP error 409\n"
check("result: 409", ps.result("vie01", "pgw04"), "retry")
fs[RF] = "rc 1\nwget: server returned error: HTTP/1.1 500 Internal Server Error"
check("result: 500", ps.result("vie01", "pgw04"), "retry")
fs[RF] = "rc 1\nwget: download timed out"
check("result: timeout", ps.result("vie01", "pgw04"), "retry")
fs[RF] = "rc 8\nHTTP error 400\n"
check("result: 400", ps.result("vie01", "pgw04"), "rejected")
fs[RF] = "rc 1\nwget: server returned error: HTTP/1.1 400 Bad Request"
check("result: busybox 400", ps.result("vie01", "pgw04"), "rejected")
fs[RF] = "rc 0\nDownloading 'x'\nWriting to 'y'\nDownload completed (55 bytes)\n"
check("result: 200, empty body", ps.result("vie01", "pgw04"), "confirmed")

-- health(): 3 misses switch the pgw, write the record and report with
-- backoff until the broker confirms.
for k in pairs(fs) do fs[k] = nil end
fs["/tmp/ff-Ohb0ba0u/noderoute.json"] = json.stringify(config(P3))
local st = { state = "up", hits = 5, misses = 0, tried = 0, changes = {}, penalties = 0, penalty_until = 0 }
local s = config(P3).sites.vie01
local function reports()
	local n = 0
	for _, c in ipairs(execs) do
		if c:find("/api/v3/switch", 1, true) then n = n + 1 end
	end
	return n
end
now = 2000
for t = 0, 2 do
	now = 2000 + t
	ps.health("vie01", s, "wg_c3", st, now, false, { peer = "K3", ts = 1990 }, nil, false, false)
end
local r = json.parse(fs[STATE .. "/switch.vie01"] or "")
check("health: switch record from", r and r.from, "pgw03")
check("health: switch record to", r and r.to, "pgw04")
check("health: noderoute.json follows", json.parse(fs["/tmp/ff-Ohb0ba0u/noderoute.json"]).concentrators[1].pubkey,
	"K4")
check("health: no report before handshake", reports(), 0)
local hs = { peer = "K4", ts = 2003 }
now = 2003
ps.health("vie01", s, "wg_c3", st, now, true, hs, nil, false, false)
check("health: first report", reports(), 1)
fs[RF] = "rc 1\nwget: server returned error: HTTP/1.1 409 Conflict"
now = 2005
ps.health("vie01", s, "wg_c3", st, now, true, hs, nil, false, false)
check("health: wait for backoff", reports(), 1)
now = 2006
ps.health("vie01", s, "wg_c3", st, now, true, hs, nil, false, false)
check("health: second report after 3 s", reports(), 2)
fs[RF] = nil
now = 2012
ps.health("vie01", s, "wg_c3", st, now, true, hs, nil, false, false)
check("health: in flight, no new report", reports(), 2)
fs[RF] = "rc 1\nwget: download timed out"
now = 2013
ps.health("vie01", s, "wg_c3", st, now, true, hs, nil, false, false)
check("health: third report after the result", reports(), 3)
fs[RF] = 'rc 0\n{"Message":"OK","site":"vie01","pgw":"pgw04","hold":900}'
now = 2014
ps.health("vie01", s, "wg_c3", st, now, true, hs, nil, false, false)
check("health: report done", st.report, nil)
r = json.parse(fs[STATE .. "/switch.vie01"] or "")
check("health: record confirmed", r and r.confirmed, 2014)

-- 400: no more reports.
st.report = { pgw = "pgw04", since = 2003, next = 0, n = 1 }
fs[RF] = "rc 1\nwget: server returned error: HTTP/1.1 400 Bad Request"
now = 2100
local n = reports()
ps.health("vie01", s, "wg_c3", st, now, true, hs, nil, false, false)
check("health: 400 stops the report", st.report == nil and reports() == n, true)

-- Send errors: no misses for send_error_max seconds, then misses count.
st = { state = "up", hits = 5, misses = 0, tried = 0, changes = {}, penalties = 0, penalty_until = 0 }
fs[STATE .. "/switch.vie01"] = nil
for t = 0, T.send_error_max - 1 do
	now = 3000 + t
	ps.health("vie01", s, "wg_c3", st, now, false, { peer = "K4", ts = 2990 }, nil, false, true)
end
check("senderr: no switch within send_error_max", fs[STATE .. "/switch.vie01"], nil)
check("senderr: no misses", st.misses, 0)
for t = 0, 2 do
	now = 3000 + T.send_error_max + t
	ps.health("vie01", s, "wg_c3", st, now, false, { peer = "K4", ts = 2990 }, nil, false, true)
end
check("senderr: switch after send_error_max", json.parse(fs[STATE .. "/switch.vie01"] or "{}").to, "pgw05")

os.exit(failed == 0 and 0 or 1)

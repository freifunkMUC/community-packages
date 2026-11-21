-- Test of parker/carry.lua: traffic from the pgw as a second liveness check.
-- Run: lua5.1 tests/carry-test.lua (from the package directory).

package.path = "luasrc/usr/share/lua/?.lua;" .. package.path
local carry = require("parker.carry")

local failed = 0
local function check(name, ok)
	print((ok and "PASS " or "FAIL ") .. name)
	if not ok then failed = failed + 1 end
end

local T = {}
for k, v in pairs(carry.defaults) do T[k] = v end

-- A tunnel as parker-sites.lua sees it: one tick each second, 3 misses
-- move to the next pgw. Returns the tick of the first pgw switch, or nil.
local function run(ticks, opts)
	local c, misses, hits, rx, switched = carry.new(), 0, 0, 0, nil
	local up = opts.up ~= false
	for now = 1, ticks do
		rx = rx + (opts.rate and opts.rate(now) or 0)
		carry.sample(c, opts.peer and opts.peer(now) or "pgw01", rx, T)
		local ok = opts.ok(now)
		local late = opts.late and opts.late(now) or false
		local v = carry.judge(c, T, now, ok, late, up)
		if v == "hit" then
			hits, misses = hits + 1, 0
		elseif v == "miss" then
			hits, misses = 0, misses + 1
		end
		if misses >= 3 and not switched then
			switched = now
		end
	end
	return switched, hits, c
end

local function after(t) return function(now) return now < t end end
local function always(v) return function() return v end end

-- Idle: no traffic. Probes fail at tick 20: switch after 3 misses, as today.
check("idle failover after 3 misses", run(60, { ok = after(20) }) == 22)

-- Download at 1 MB/s, probes lost from tick 20 (bloat): no switch for 30 s.
local big = always(1000000)
check("download keeps pgw until max defer", run(60, { ok = after(20), rate = big }) == 19 + T.carry_max + 2)

-- Bloat with late replies every 2 s: the answers reset the max defer, no switch.
check("late replies keep pgw", run(120, {
	ok = after(20), rate = big, late = function(now) return now >= 20 and now % 2 == 0 end,
}) == nil)

-- pgw dies during the download: rx stops at once, switch after 3 misses.
-- The window carries for one more tick: switch at 23 instead of 22.
check("dead pgw under load: switch 4 s after rx stops",
	run(60, { ok = after(20), rate = function(now) return now < 20 and 1000000 or 0 end }) == 23)

-- rx stops 1 tick later than the probes: the window still carries then.
check("dead pgw, rx stops late: switch within 6 s",
	(run(60, { ok = after(20), rate = function(now) return now < 25 and 1000000 or 0 end }) or 99) <= 20 + 6 + 3)

-- pgw stops during a download: the data in flight comes 1 s later, then
-- retransmits trickle in. The trickle ticks do not count: switch at 24.
check("drain and trickle after a cut do not carry", run(60, {
	ok = after(20), rate = function(now)
		if now < 20 then return 600000 elseif now == 20 then return 300000 end
		return 12000
	end,
}) == 24)

-- Trickle below 48 KB in 3 s: no carry.
check("trickle does not carry", run(60, { ok = after(20), rate = always(15000) }) == 22)

-- One burst in 3 ticks: no carry (needs 2 of 3 ticks).
check("single burst does not carry", run(60, {
	ok = after(20), rate = function(now) return now % 3 == 0 and 1000000 or 0 end,
}) == 22)

-- Keepalives only (32 bytes each 25 s): no carry.
check("keepalives do not carry", run(60, {
	ok = after(20), rate = function(now) return now % 25 == 0 and 32 or 0 end,
}) == 22)

-- Site down: carry never stops misses, so it never makes a site up.
check("no carry on a down site", run(60, { ok = after(20), rate = big, up = false }) == 22)

-- Carry gives no hits.
local _, hits = run(40, { ok = after(20), rate = big })
check("carry counts no hits", hits == 19)

-- New pgw (peer change): new history, no carry for the first ticks.
check("peer change resets history", run(60, {
	ok = after(20), rate = big, peer = function(now) return now < 20 and "pgw01" or "pgw02" end,
}) == 22)

-- Counter reset (peer re-added): no negative delta, new history.
local c = carry.new()
carry.sample(c, "p", 5000000, T)
carry.sample(c, "p", 100, T)
check("counter reset starts new history", #c.deltas == 0 and c.last == 100)

-- No answer before carry started: no defer.
check("no answer yet: no carry", run(60, { ok = always(false), rate = big }) == 3)

-- carry_bytes = 0 disables carry.
T.carry_bytes = 0
check("carry_bytes 0 disables", run(60, { ok = after(20), rate = big }) == 22)
T.carry_bytes = carry.defaults.carry_bytes

if failed > 0 then
	print(failed .. " test(s) failed")
	os.exit(1)
end
print("all tests passed")

-- Test of parker/ragoodbye.lua: the node starts the router lifetime 0 in the
-- background (make before break) and cancels it when it routes again.
-- Run: lua5.1 tests/ragoodbye-test.lua (from the package directory).

local files = {}
local executed = {}
package.preload["util"] = function()
	return {
		read_file = function(path) return files[path] end,
		log = function() end,
	}
end
package.path = "luasrc/usr/share/lua/?.lua;" .. package.path
os.execute = function(cmd) table.insert(executed, cmd) return 0 end -- luacheck: ignore 122
os.remove = function(path) files[path] = nil end -- luacheck: ignore 122

local ragoodbye = require("parker.ragoodbye")

local failed = 0
local function check(name, ok)
	print((ok and "PASS " or "FAIL ") .. name)
	if not ok then failed = failed + 1 end
end
local function ran(pattern)
	for _, cmd in ipairs(executed) do
		if cmd:find(pattern) then return true end
	end
	return false
end
local function lifetime0_now()
	for _, cmd in ipairs(executed) do
		if cmd:find("uradvd", 1, true) and cmd:find("--default-lifetime 0", 1, true) then return true end
	end
	return false
end

-- Multi-site: all prefixes of the sites, in the background, no uradvd now.
files["/tmp/parker-sites/ra-state"] = "2001:db8:1::/64,180\n2001:db8:2::/64,0\n"
check("send returns true", ragoodbye.send())
check("radvd daemons stopped", ran("parker%-radvd stop") and ran("gluon%-radvd stop"))
check("waiter started in the background",
	ran("^/usr/sbin/parker%-ra%-goodbye 180 8 600 2001:db8:1::/64 2001:db8:2::/64 >/dev/null 2>&1 &$"))
check("no router lifetime 0 at once", not lifetime0_now())

-- Single site: the prefix of /tmp/range6.
executed = {}
files["/tmp/parker-sites/ra-state"] = nil
files["/tmp/range6"] = "2001:db8:5::/64\n"
ragoodbye.send()
check("single site prefix", ran("parker%-ra%-goodbye 180 8 600 2001:db8:5::/64 >"))

-- Nothing to announce: no waiter.
executed = {}
files["/tmp/range6"] = nil
check("send returns false without prefix", ragoodbye.send() == false)
check("no waiter without prefix", not ran("parker%-ra%-goodbye"))

-- Cancel: only the waiter process gets the signal.
executed = {}
files[ragoodbye.PID_FILE] = "1234\n"
files["/proc/1234/cmdline"] = "/bin/sh\0/usr/sbin/parker-ra-goodbye\0" .. "180\0"
check("cancel kills the waiter", ragoodbye.cancel() and ran("^kill 1234 "))

executed = {}
files["/proc/1234/cmdline"] = "/usr/sbin/dropbear\0"
check("cancel ignores a reused pid", not ragoodbye.cancel() and not ran("kill"))
check("stale pid file removed", files[ragoodbye.PID_FILE] == nil)
check("cancel without pid file", not ragoodbye.cancel())

-- send() cancels an older waiter first.
executed = {}
files[ragoodbye.PID_FILE] = "77"
files["/proc/77/cmdline"] = "sh\0/usr/sbin/parker-ra-goodbye\0"
files["/tmp/range6"] = "2001:db8:5::/64"
ragoodbye.send()
local kill_at, start_at
for i, cmd in ipairs(executed) do
	if cmd:find("^kill 77") then kill_at = i end
	if cmd:find("parker%-ra%-goodbye 180") then start_at = i end
end
check("send cancels the old waiter before it starts a new one", kill_at and start_at and kill_at < start_at)

os.exit(failed == 0 and 0 or 1)

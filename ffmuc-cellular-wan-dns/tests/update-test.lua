#!/usr/bin/env lua
-- Host test for update.lua with mocked ubus, uci and files.
-- luacheck: globals io os
--
-- Usage: lua tests/update-test.lua [path/to/gluon-wan-dnsmasq/update.lua]
--
-- With the path to the update.lua of gluon-wan-dnsmasq, the test also runs
-- that script. Without it, a stub writes the same output as that script.

local dir = arg[0]:match('^(.*)/tests/[^/]*$') or '.'
local SCRIPT = dir .. '/luasrc/lib/gluon/ffmuc-cellular-wan-dns/update.lua'
local GLUON_UPDATE = arg[1]
local INTERFACE_D = { 'wan', 'wan6', 'cellular', 'cellular_4' }
local RESOLV = '/var/gluon/wan-dnsmasq/resolv.conf'

local FALLBACK = '# ffmuc-cellular-wan-dns fallback\n'
	.. 'nameserver 5.1.66.255\n'
	.. 'nameserver 185.150.99.255\n'
	.. 'nameserver 2001:678:e68:f000::\n'
	.. 'nameserver 2001:678:ed0:f000::\n'

-- State of one test case.
local files, ifaces, config, executed

local function reset()
	files = {}
	ifaces = {}
	executed = 0
	config = {
		network = { cellular = { ['.type'] = 'interface' } },
		['gluon-wan-dnsmasq'] = {},
		['ffmuc-cellular-wan-dns'] = {
			fallback = {
				['.type'] = 'fallback',
				enabled = '1',
				server = {
					'5.1.66.255', '185.150.99.255',
					'2001:678:e68:f000::', '2001:678:ed0:f000::',
				},
			},
		},
	}
end

local function iface(name, up, inactive_dns, device)
	ifaces[name] = {
		up = up,
		device = device or 'wwan0',
		['dns-server'] = {},
		inactive = { ['dns-server'] = inactive_dns or {} },
	}
end

package.preload['ubus'] = function()
	return {
		connect = function()
			return {
				call = function(_, obj, method)
					assert(method == 'status')
					local s = ifaces[obj:match('^network%.interface%.(.*)$')]
					if not s then
						error('Not found')
					end
					return s
				end,
			}
		end,
	}
end

package.preload['simple-uci'] = function()
	local cursor = {}
	function cursor.get(_, pkg, sec, opt)
		local s = config[pkg] and config[pkg][sec]
		if not s then return nil end
		if opt == nil then return s['.type'] end
		return s[opt]
	end
	function cursor.get_bool(self, ...)
		local v = self:get(...)
		return v == '1' or v == 'true' or v == 'on' or v == 'yes' or v == true
	end
	function cursor.get_list(self, ...)
		return self:get(...) or {}
	end
	function cursor.get_first(_, pkg, typ, opt)
		for _, s in pairs(config[pkg] or {}) do
			if s['.type'] == typ then return s[opt] end
		end
	end
	return { cursor = function() return cursor end }
end

package.preload['gluon.util'] = function()
	return {
		glob = function() return { 'interface.d' } end,
		readfile = function(path) return files[path] end,
	}
end

package.preload['posix.sys.stat'] = function()
	return { mkdir = function() end }
end

-- Map file access of the scripts to the in-memory files.
local real_open, real_lines, real_rename, real_execute = io.open, io.lines, os.rename, os.execute

local function sandbox(fn)
	io.lines = function(path)
		assert(path == 'interface.d', path)
		local i = 0
		return function()
			i = i + 1
			return INTERFACE_D[i]
		end
	end
	io.open = function(path, mode)
		assert(mode == 'w', path)
		local buf = {}
		return {
			write = function(_, s) table.insert(buf, s) end,
			close = function() files[path] = table.concat(buf) end,
		}
	end
	os.rename = function(from, to)
		files[to] = files[from]
		files[from] = nil
	end
	os.execute = function(cmd)
		assert(cmd == '/lib/gluon/wan-dnsmasq/update.lua', cmd)
		executed = executed + 1
		local run
		if GLUON_UPDATE then
			run = assert(loadfile(GLUON_UPDATE))
		else
			run = function()
				local new = ''
				for _, name in ipairs(INTERFACE_D) do
					local s = ifaces[name]
					for _, srv in ipairs(s and s.inactive['dns-server'] or {}) do
						new = new .. 'nameserver ' .. srv .. '\n'
					end
				end
				if new ~= (files[RESOLV] or '') then files[RESOLV] = new end
			end
		end
		run()
		return 0
	end
	local ok, err = pcall(fn)
	io.open, io.lines, os.rename, os.execute = real_open, real_lines, real_rename, real_execute
	assert(ok, err)
end

local function run_script()
	sandbox(assert(loadfile(SCRIPT)))
end

local function run_gluon_hotplug()
	sandbox(function() os.execute('/lib/gluon/wan-dnsmasq/update.lua') end)
	executed = 0
end

local failed, passed = 0, 0
local function check(name, cond, detail)
	if cond then
		passed = passed + 1
		print('PASS ' .. name)
	else
		failed = failed + 1
		print('FAIL ' .. name .. (detail and (': ' .. detail) or ''))
	end
end


-- 1. Field case: cellular_4 reports IPv4 DNS in 'inactive'. The parent
-- 'cellular' (qmi, IPv6) reports none. 50-gluon-wan-dnsmasq runs first.
reset()
iface('cellular', true, {})
iface('cellular_4', true, { '192.0.2.53', '192.0.2.54' })
run_gluon_hotplug()
run_script()
check('cellular_4 servers are kept', files[RESOLV] == 'nameserver 192.0.2.53\nnameserver 192.0.2.54\n',
	files[RESOLV])
check('script does not call update.lua', executed == 0)

-- 2. IPv6 DNS on the parent 'cellular'.
reset()
iface('cellular', true, { '2001:db8::53' })
iface('cellular_4', true, {})
run_gluon_hotplug()
run_script()
check('cellular servers are kept', files[RESOLV] == 'nameserver 2001:db8::53\n', files[RESOLV])

-- 3. Cellular is up, but no interface reports DNS: write the fallback list.
reset()
iface('cellular', true, {})
iface('cellular_4', true, {})
files[RESOLV] = ''
run_script()
check('fallback is written', files[RESOLV] == FALLBACK, files[RESOLV])
check('fallback does not call update.lua', executed == 0)

-- 4. The fallback stays stable when nothing changes.
local before = files[RESOLV]
run_script()
check('fallback is stable', files[RESOLV] == before)

-- 5. DNS arrives later: the real servers replace the fallback list.
iface('cellular_4', true, { '192.0.2.53' })
run_gluon_hotplug()
run_script()
check('real servers replace fallback', files[RESOLV] == 'nameserver 192.0.2.53\n', files[RESOLV])

-- 6. Cellular is down and reports no DNS: no fallback.
reset()
iface('cellular', false, {})
files[RESOLV] = ''
run_script()
check('no fallback when cellular is down', files[RESOLV] == '')

-- 7. Node without cellular: the script does nothing.
reset()
config.network.cellular = nil
iface('wan', true, {})
files[RESOLV] = ''
run_script()
check('no change without cellular', files[RESOLV] == '' and executed == 0)

-- 8. Node without cellular, with WAN DNS: the script does not call update.lua.
reset()
config.network.cellular = nil
iface('wan', true, { '192.0.2.1' })
run_script()
check('no update.lua call without cellular', executed == 0 and files[RESOLV] == nil)

-- 9. Static list of gluon-wan-dnsmasq: the script does nothing.
reset()
config['gluon-wan-dnsmasq'].s = { ['.type'] = 'static', server = { '198.51.100.1' } }
iface('cellular', true, {})
files[RESOLV] = 'nameserver 198.51.100.1\n'
run_script()
check('static list is kept', files[RESOLV] == 'nameserver 198.51.100.1\n' and executed == 0)

-- 10. Fallback disabled.
reset()
config['ffmuc-cellular-wan-dns'].fallback.enabled = '0'
iface('cellular', true, {})
files[RESOLV] = ''
run_script()
check('no fallback when disabled', files[RESOLV] == '')

-- 11. Stale servers and no DNS now (missed ifdown of an uplink): fallback.
reset()
iface('cellular', true, {})
files[RESOLV] = 'nameserver 192.0.2.99\n'
run_script()
check('stale servers are replaced by fallback', files[RESOLV] == FALLBACK, files[RESOLV])

print(string.format('%d passed, %d failed', passed, failed))
os.exit(failed == 0 and 0 or 1)

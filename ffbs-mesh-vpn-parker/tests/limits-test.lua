-- Test of parker/limits.lua.
-- Run: luajit tests/limits-test.lua (from the package directory).

package.path = 'luasrc/usr/share/lua/?.lua;' .. package.path

local limits = require('parker.limits')

local failed = 0
local function check(name, cond)
	print((cond and 'PASS ' or 'FAIL ') .. name)
	if not cond then failed = failed + 1 end
end

local MIB = 1024
local POOL20 = 4093
-- MemTotal of real nodes: 64 MB, 128 MB, 256 MB.
local RAM64, RAM128, RAM256 = 57 * MIB, 121 * MIB, 230 * MIB

-- Default mode: 1024 leases, ping check and DNS cache stay at the dnsmasq
-- default, small tables for every RAM size.
for _, mem in ipairs({ RAM64, RAM128, RAM256 }) do
	local d = limits.dnsmasq(mem, false, POOL20)
	check('default ' .. mem .. ': lease max 1024', d.dhcpleasemax == 1024)
	check('default ' .. mem .. ': ping check on', d.noping == nil)
	check('default ' .. mem .. ': dnsmasq cache', d.cachesize == nil)
	check('default ' .. mem .. ': gc_thresh3 4096', limits.neigh(mem, false)[3] == 4096)
end

-- Event mode: full pool, no ping, larger cache and tables by RAM.
local e = limits.dnsmasq(RAM256, true, POOL20)
check('event: lease max is the pool', e.dhcpleasemax == POOL20)
check('event: no ping', e.noping == 1)
check('event: cache 4096', e.cachesize == 4096)
check('event small pool: lease max at least 1024', limits.dnsmasq(RAM256, true, 253).dhcpleasemax == 1024)
check('event 128 MB: cache 2048', limits.dnsmasq(RAM128, true, POOL20).cachesize == 2048)

-- Event mode needs 128 MB RAM. On a smaller node the setting has no effect.
check('128 MB node: event mode available', limits.available(RAM128))
check('64 MB node: event mode not available', not limits.available(RAM64))
local small = limits.dnsmasq(RAM64, true, POOL20)
check('64 MB node, event set: default lease max', small.dhcpleasemax == 1024 and small.noping == nil)
check('64 MB node, event set: default sysctl',
	limits.sysctl_text(RAM64, true, 3712) == limits.sysctl_text(RAM64, false, 3712))
check('event 256 MiB: gc_thresh3 16384', limits.neigh(RAM256, true)[3] == 16384)
check('event 128 MiB: gc_thresh3 8192', limits.neigh(RAM128, true)[3] == 8192)

-- conntrack: never lower than the kernel value.
check('conntrack default 256 MiB', limits.conntrack(RAM256, false, 14848) == 16384)
check('conntrack event 256 MiB', limits.conntrack(RAM256, true, 14848) == 65536)
check('conntrack event 128 MB', limits.conntrack(RAM128, true, 7424) == 32768)
check('conntrack 64 MiB: kernel value', limits.conntrack(RAM64, true, 3712) == nil)
check('conntrack large kernel value kept', limits.conntrack(2048 * MIB, false, 262144) == nil)

local text = limits.sysctl_text(RAM256, true, 14848)
check('sysctl text: ipv6 gc_thresh3', text:find('net.ipv6.neigh.default.gc_thresh3=16384\n', 1, true) ~= nil)
check('sysctl text: conntrack', text:find('net.netfilter.nf_conntrack_max=65536\n', 1, true) ~= nil)
check('sysctl text: no conntrack on 64 MiB',
	limits.sysctl_text(RAM64, false, 3712):find('conntrack', 1, true) == nil)

-- apply_sysctl writes only on a change.
local path = os.tmpname()
os.remove(path)
limits.mem_total = function() return RAM256 end
limits.conntrack_default = function() return 14848 end
local sysctl_calls = 0
local execute = os.execute
os.execute = function() sysctl_calls = sysctl_calls + 1; return 0 end -- luacheck: ignore 122
check('apply: first write', limits.apply_sysctl(false, path) == true)
check('apply: no change', limits.apply_sysctl(false, path) == false)
check('apply: event mode changes it', limits.apply_sysctl(true, path) == true)
check('apply: sysctl ran twice', sysctl_calls == 2)
os.execute = execute -- luacheck: ignore 122
os.remove(path)

check('enabled', limits.enabled('1') and limits.enabled(true) and not limits.enabled('0') and not limits.enabled(nil))

-- Event mode: same base, /20 mask.
check('range4: default keeps /22', limits.range4('10.80.96.0/22', RAM256, false) == '10.80.96.0/22')
check('range4: event widens /22 to /20', limits.range4('10.80.96.0/22', RAM256, true) == '10.80.96.0/20')
check('range4: event on 128 MB widens', limits.range4('10.80.96.0/22', 123904, true) == '10.80.96.0/20')
check('range4: no event below 128 MB', limits.range4('10.80.96.0/22', RAM64, true) == '10.80.96.0/22')
check('range4: /20 stays', limits.range4('10.73.0.0/20', RAM256, true) == '10.73.0.0/20')
check('range4: /16 is not narrowed', limits.range4('10.80.0.0/16', RAM256, true) == '10.80.0.0/16')
check('range4: base off a /20 boundary stays', limits.range4('10.80.100.0/22', RAM256, true) == '10.80.100.0/22')
check('range4: invalid stays', limits.range4('nonsense', RAM256, true) == 'nonsense')
check('range4: nil stays', limits.range4(nil, RAM256, true) == nil)

-- Lease file after event mode goes off: /20 -> /22, max 3.
local leases = table.concat({
	'100 02:00:00:00:00:01 10.73.0.10 a *',
	'400 02:00:00:00:00:02 10.73.11.12 b *',
	'300 02:00:00:00:00:03 10.73.3.254 c *',
	'200 02:00:00:00:00:04 10.73.1.1 d *',
	'duid 00:01:02',
	'500 1234 2001:db8::5 e *',
}, '\n') .. '\n'
local trimmed, dropped = limits.trim_leases(leases, '10.73.0.0/22', 3)
check('trim: 2 leases removed', dropped == 2)
check('trim: outside /22 removed', not trimmed:find('10.73.11.12', 1, true))
check('trim: oldest removed', not trimmed:find('10.73.0.10', 1, true))
check('trim: newer leases and duid stay', trimmed:find('10.73.3.254', 1, true) and trimmed:find('10.73.1.1', 1, true)
	and trimmed:find('duid', 1, true) and trimmed:find('2001:db8::5', 1, true))
check('trim: fits, no change', select(2, limits.trim_leases(leases, '10.73.0.0/20', 5)) == 0)
check('trim: no range, count only', select(2, limits.trim_leases(leases, nil, 1)) == 4)
check('trim: empty file', limits.trim_leases('', '10.73.0.0/22', 3) == '')

check('pool: /22', limits.pool('10.80.96.0/22') == 1021)
check('pool: /20', limits.pool('10.80.96.0/20') == 4093)
check('pool: invalid', limits.pool('nonsense') == nil and limits.pool(nil) == nil)

if failed > 0 then
	print(failed .. ' FAILED')
	os.exit(1)
end
print('all passed')

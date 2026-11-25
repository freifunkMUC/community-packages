#!/usr/bin/lua

local RESOLV_CONF = '/var/gluon/wan-dnsmasq/resolv.conf'
local MARKER = '# ffmuc-cellular-wan-dns fallback\n'
local CELLULAR = { 'cellular', 'cellular_4' }


local stat = require 'posix.sys.stat'
local ubus = require('ubus').connect()
local uci = require('simple-uci').cursor()
local util = require 'gluon.util'


-- Do nothing on nodes without a Gluon cellular uplink.
if uci:get('network', 'cellular') ~= 'interface' then
	return
end

-- gluon-wan-dnsmasq uses the static list. Do not change it.
local static = uci:get_first('gluon-wan-dnsmasq', 'static', 'server')
if type(static) == 'table' and #static > 0 then
	return
end


local function status(iface)
	local ok, s = pcall(function()
		return ubus:call('network.interface.' .. iface, 'status', {})
	end)
	if ok and type(s) == 'table' then
		return s
	end
end

-- Gluon sets peerdns 0 on its uplinks. netifd then shows the servers in
-- 'inactive'. update.lua reads them there.
local function has_dns(s)
	local servers = s.inactive and s.inactive['dns-server']
	return type(servers) == 'table' and #servers > 0
end

local function handled_interfaces()
	local interfaces = {}
	for _, path in ipairs(util.glob('/lib/gluon/wan-dnsmasq/interface.d/*')) do
		for iface in io.lines(path) do
			table.insert(interfaces, iface)
		end
	end
	return interfaces
end


-- An uplink reports DNS servers. The update.lua of gluon-wan-dnsmasq writes
-- them in the same hotplug event, and replaces the fallback list.
for _, iface in ipairs(handled_interfaces()) do
	local s = status(iface)
	if s and has_dns(s) then
		return
	end
end


local cellular_up = false
for _, iface in ipairs(CELLULAR) do
	local s = status(iface)
	if s and s.up then
		cellular_up = true
	end
end

if not cellular_up then
	return
end

-- The cellular uplink is up, but no uplink reports a DNS server. Without the
-- fallback list, update.lua leaves the file empty.
if not uci:get_bool('ffmuc-cellular-wan-dns', 'fallback', 'enabled') then
	return
end

local servers = uci:get_list('ffmuc-cellular-wan-dns', 'fallback', 'server')
if #servers == 0 then
	return
end

local current = util.readfile(RESOLV_CONF) or ''
local new = MARKER
for _, server in ipairs(servers) do
	new = new .. 'nameserver ' .. server .. '\n'
end

if new ~= current then
	stat.mkdir('/var/gluon')
	stat.mkdir('/var/gluon/wan-dnsmasq')

	local f = io.open(RESOLV_CONF .. '.tmp', 'w')
	f:write(new)
	f:close()

	os.rename(RESOLV_CONF .. '.tmp', RESOLV_CONF)
end

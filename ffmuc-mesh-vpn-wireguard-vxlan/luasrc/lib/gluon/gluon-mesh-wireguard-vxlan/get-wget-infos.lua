local json = require 'jsonc'
local util = require 'gluon.util'
local syslog = require 'posix.syslog'

local function readline(path)
	local content = util.readfile(path)
	return content and util.trim(content)
end

local function optional(format, value)
	return value and string.format(format, value) or ''
end

local board = json.parse(util.exec('ubus call system board') or '') or {}
local release = board.release or {}

local info = {
	gluon_version = readline('/lib/gluon/gluon-version'),
	board_name = board.board_name,
	openwrt_version = release.version,
	kernel = board.kernel,
	target = release.target,
	firmware_release = readline('/lib/gluon/release'),
}

-- procd omits board_name on x86 boards without DMI vendor
local headers = {
	{ 'gluon_version', 'X-Gluon-Version' },
	{ 'board_name', 'X-Board-Name', optional = true },
	{ 'openwrt_version', 'X-Openwrt-Version' },
	{ 'kernel', 'X-Kernel-Version' },
	{ 'target', 'X-Target-Name' },
	{ 'firmware_release', 'X-Firmware-Version' },
}

syslog.openlog('checkuplink')

for _, header in ipairs(headers) do
	local key = header[1]
	if info[key] == '' then
		info[key] = nil
	end
	if not info[key] then
		syslog.syslog(header.optional and syslog.LOG_NOTICE or syslog.LOG_ERR, 'Node info ' .. key .. ' is missing')
	end
end

local platform = {}
if info.kernel then
	table.insert(platform, 'kernel/' .. info.kernel)
end
if info.target then
	table.insert(platform, info.target)
end

print('gluon' .. optional('/%s', info.gluon_version) .. optional(' (%s)', info.board_name) ..
	' OpenWrt' .. optional('/%s', info.openwrt_version) ..
	optional(' (%s)', platform[1] and table.concat(platform, '; ')) ..
	' firmware' .. optional('/%s', info.firmware_release))

for _, header in ipairs(headers) do
	local value = info[header[1]]
	if value then
		print(header[2] .. ': ' .. value)
	end
end

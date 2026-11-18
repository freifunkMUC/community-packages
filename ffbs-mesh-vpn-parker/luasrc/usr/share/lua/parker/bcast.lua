-- Send a burst of batman-adv broadcasts after batman-adv starts.
--
-- batman-adv starts the broadcast sequence number of bat0 at 1. Gluon
-- creates bat0 again at each boot and at each change of gw_mode. The other
-- nodes keep the last sequence number of each originator for about 200 s
-- and drop a broadcast with a number up to 64 below that number as a
-- duplicate. Thus they can drop all broadcasts of this node (router
-- advertisements included) until its number passes the old one.
--
-- A burst of COUNT broadcasts that the other nodes receive moves the
-- number past this window at once. batman-adv also gives a number to a
-- broadcast that no neighbour receives, so the burst waits until bat0 has
-- a neighbour.
--
-- The burst is IPv4 UDP to 255.255.255.255, port 9 (discard), sent
-- directly on bat0: the Ethernet broadcast address always makes a
-- batman-adv broadcast, and no bridge filter is in the path.

local posix = require("posix")
local socket = require("posix.sys.socket")

local bcast = {}

-- BATADV_BCAST_MAX_AGE (64) plus a margin.
bcast.COUNT = 70

local IFACE = "bat0"
local PORT = 9

local function is_up(iface)
	local f = io.open("/sys/class/net/" .. iface .. "/flags")
	if not f then
		return false
	end
	local flags = tonumber(f:read("*l") or "", 16)
	f:close()
	return flags ~= nil and flags % 2 == 1
end

-- batman-adv knows at least one neighbour.
local function has_neighbour()
	local p = io.popen("batctl meshif " .. IFACE .. " n -n -H 2>/dev/null")
	local data = p:read("*a")
	p:close()
	return data:match("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x") ~= nil
end

-- Wait up to timeout seconds until bat0 is up and has a neighbour, then
-- send the burst. Returns the number of packets sent.
function bcast.burst(timeout)
	timeout = timeout or 0
	local waited = 0
	while not (is_up(IFACE) and has_neighbour()) do
		if waited >= timeout then
			return 0
		end
		posix.unistd.sleep(1)
		waited = waited + 1
	end
	local fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
	if not fd then
		return 0
	end
	local sent = 0
	if socket.setsockopt(fd, socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
			and socket.setsockopt(fd, socket.SOL_SOCKET, socket.SO_BINDTODEVICE, IFACE) then
		local dest = { family = socket.AF_INET, addr = "255.255.255.255", port = PORT }
		for _ = 1, bcast.COUNT do
			if socket.sendto(fd, "parker", dest) then
				sent = sent + 1
			end
		end
	end
	posix.unistd.close(fd)
	return sent
end

return bcast

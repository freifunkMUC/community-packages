-- Traffic as a second liveness check of a pgw ("carry").
--
-- On a lossy or bloated uplink (for example LTE during a big download), the
-- echo reply of the probe can come after more than 1 s or get lost, although
-- the pgw works. Then parker-sites counts misses and moves the tunnel to
-- another pgw or site, and the download breaks.
--
-- WireGuard counts the received bytes (rx) of a peer only for packets that
-- it authenticated. When rx of the current pgw grows, this pgw sends. A
-- tunnel "carries" when rx grew by at least carry_bytes in the last
-- carry_window ticks, and in at least carry_ticks of these ticks. TX proves
-- nothing and is not used.
--
-- While a tunnel of a site that is up carries, a missed probe is not
-- counted as a miss (and not as a hit). The probe then waits up to
-- probe_wait_busy seconds for the reply; a late reply counts as an answer.
-- When no answer came for carry_max seconds, misses count again.
--   * Carry never makes a pgw or site up: only real hits do that.
--   * A tunnel without traffic is not affected.
--   * carry_bytes = 0 disables carry.

local carry = {}

carry.defaults = {
	carry_bytes = 49152,
	carry_window = 3,
	carry_ticks = 2,
	carry_max = 30,
	probe_wait_busy = 3,
}

-- The carry state of a tunnel, kept in the site state.
function carry.new()
	return { deltas = {} }
end

-- Add the rx counter of this tick. peer is the current pgw of the tunnel.
-- A new peer or a lower counter starts a new history.
function carry.sample(c, peer, rx, T)
	if peer == nil or rx == nil then
		c.peer, c.last, c.deltas = nil, nil, {}
		return
	end
	if c.peer ~= peer or c.last == nil or rx < c.last then
		c.peer, c.last, c.deltas = peer, rx, {}
		return
	end
	table.insert(c.deltas, rx - c.last)
	c.last = rx
	while #c.deltas > T.carry_window do
		table.remove(c.deltas, 1)
	end
end

-- Does the tunnel carry traffic from the pgw now?
function carry.active(c, T)
	if (T.carry_bytes or 0) <= 0 or #c.deltas < T.carry_window then
		return false
	end
	local sum, ticks = 0, 0
	for _, d in ipairs(c.deltas) do
		sum = sum + d
		if d > 0 then
			ticks = ticks + 1
		end
	end
	return sum >= T.carry_bytes and ticks >= T.carry_ticks
end

-- The result of the probe of this tick: "hit", "miss" or "carry".
-- ok: the reply of this tick came. late: a reply of an earlier tick came.
-- up: the site is up.
function carry.judge(c, T, now, ok, late, up)
	if ok then
		c.answer = now
		return "hit"
	end
	if late then
		c.answer = now
	end
	if up and carry.active(c, T) and c.answer ~= nil and now - c.answer < T.carry_max then
		return "carry"
	end
	return "miss"
end

return carry

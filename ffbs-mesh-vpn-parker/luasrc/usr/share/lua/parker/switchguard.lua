-- The config service selects the pgw of each site. After 3 missed probes,
-- parker-sites moves the tunnel to the next pgw of the site and reports
-- the switch. Until the config service knows the switch, a fetched config
-- can still name the pgw that the node left. The guard prevents that the
-- node goes back to it:
--   * A switch writes a record: from (left pgw), to (new pgw), since.
--   * The node reports the switch again with backoff until the config
--     service confirms it (2xx). When the answer names a pgw, it must be
--     the reported pgw.
--   * While the switch is unconfirmed (at most switch_guard_max seconds)
--     or younger than switch_hold seconds, a fetched config that names the
--     left pgw gets the new pgw.
--   * Each other config is applied as it is, and the record is removed
--     when the config names another pgw (rebalance or drain).
-- The record is in /tmp: after a reboot, the node uses the config service
-- answer.

local guard = {}

guard.defaults = {
	switch_hold = 300,
	switch_guard_max = 1800,
	report_retry = 3,
	report_retry_max = 60,
}

local function find_by(list, key, value)
	for _, item in ipairs(list or {}) do
		if tostring(item[key]) == tostring(value) then
			return item
		end
	end
	return nil
end

-- What to do with the config of a site. rec: the switch record, conc: the
-- concentrator of the site in the config.
--   "keep":   the config names the left pgw, use rec.to instead.
--   "match":  the config names rec.to.
--   "expire": apply the config as it is and remove the record.
function guard.decide(rec, site, conc, now, T)
	local age = now - (tonumber(rec.since) or 0)
	if age < 0 or (age >= T.switch_hold and (rec.confirmed or age >= T.switch_guard_max)) then
		return "expire"
	end
	local to = find_by(site.pgws, "name", rec.to)
	if not to or not conc then
		return "expire"
	end
	local from = find_by(site.pgws, "name", rec.from)
	if from and conc.pubkey == from.pubkey and conc.pubkey ~= to.pubkey then
		return "keep"
	end
	if conc.pubkey == to.pubkey then
		return "match"
	end
	return "expire"
end

-- Seconds after report attempt n (1, 2, ...) before the next attempt.
function guard.retry_after(n, T)
	return math.min(T.report_retry * 2 ^ math.max(n - 1, 0), T.report_retry_max)
end

-- The pgw that the config service names in its answer, or nil.
function guard.chosen(body)
	return (body or ""):match('"pgw"%s*:%s*"([^"]*)"')
end

-- Copy the pgw fields into the concentrator.
function guard.use(conc, pgw)
	for _, k in ipairs({ "address4", "address6", "endpoint", "pubkey" }) do
		if pgw[k] ~= nil then
			conc[k] = pgw[k]
		end
	end
end

guard.find_by = find_by

return guard

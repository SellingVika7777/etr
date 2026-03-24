-- ETR (Eblan Trouble Register) server addon. SellingVika. https://sellingvika.party/etr
if not SERVER then return end

local ETR_API_BASE = "https://sellingvika.party/etr/v3"
local ETR_DEFAULT_REJECT_MSG = "You are blocked by ETR (Eblan Trouble Register).\nMore info: https://sellingvika.party/etr"
local ETR_DEFAULT_STRICT_MSG = "[ETR] Please reconnect in 15 seconds."
local STEAMID64_LEN = 17
local STEAMID64_MIN = "76561197960265728"
local STATUS_BULK_MAX = 100
local FEED_MAX = 200
local CACHE_MAX_SIZE = 10000
local RETRY_MAX = 3
local RETRY_QUEUE_MAX = 50
local WHITELIST_FILE = "etr_whitelist.txt"

local cv_apikey, cv_enabled, cv_api_base, cv_debug
local cv_cache_ttl, cv_fail_open, cv_periodic_interval, cv_strict_first
local cv_vote_reason_id, cv_kick_message

local etr_registered = false
local etr_server_id = nil
local etr_api_available = true
local etr_key_info = nil
local etr_cache = {}
local etr_cache_time = {}
local etr_check_pending = {}
local etr_whitelist = {}
local etr_retry_queue = {}
local etr_consecutive_429 = 0

local etr_rate = {
    remaining = nil,
    reset_at = 0,
    backoff_until = 0,
}

local etr_stats = {
    checks = 0,
    blocks = 0,
    api_errors = 0,
    votes = 0,
    feeds = 0,
    retries = 0,
    whitelisted = 0,
}

CreateConVar("etr_apikey", "", FCVAR_PROTECTED + FCVAR_NOTIFY, "", 0, 0)
CreateConVar("etr_enabled", "1", FCVAR_ARCHIVE, "", 0, 1)
CreateConVar("etr_api_base", ETR_API_BASE, FCVAR_ARCHIVE, "", 0, 0)
CreateConVar("etr_debug", "0", FCVAR_ARCHIVE, "", 0, 1)
CreateConVar("etr_cache_ttl", "3600", FCVAR_ARCHIVE, "", 60, 86400)
CreateConVar("etr_fail_open", "1", FCVAR_ARCHIVE, "", 0, 1)
CreateConVar("etr_periodic_interval", "600", FCVAR_ARCHIVE, "", 0, 3600)
CreateConVar("etr_strict_first", "0", FCVAR_ARCHIVE, "", 0, 1)
CreateConVar("etr_vote_reason_id", "1", FCVAR_ARCHIVE, "ETR vote reason_id for /vote endpoint", 1, 100)
CreateConVar("etr_kick_message", "", FCVAR_ARCHIVE, "Custom kick message, empty for default", 0, 0)

local function cv()
    cv_apikey = GetConVar("etr_apikey")
    cv_enabled = GetConVar("etr_enabled")
    cv_api_base = GetConVar("etr_api_base")
    cv_debug = GetConVar("etr_debug")
    cv_cache_ttl = GetConVar("etr_cache_ttl")
    cv_fail_open = GetConVar("etr_fail_open")
    cv_periodic_interval = GetConVar("etr_periodic_interval")
    cv_strict_first = GetConVar("etr_strict_first")
    cv_vote_reason_id = GetConVar("etr_vote_reason_id")
    cv_kick_message = GetConVar("etr_kick_message")
end
cv()

local function log(msg)
    if not cv_debug or cv_debug:GetInt() == 0 then return end
    print("[ETR] " .. tostring(msg))
end

local function get_reject_msg()
    local custom = cv_kick_message and cv_kick_message:GetString() or ""
    if custom ~= "" then return custom end
    return ETR_DEFAULT_REJECT_MSG
end

local function validate_base_url(url)
    if type(url) ~= "string" or url == "" then return false end
    if not url:match("^https://") then return false end
    local host = url:match("^https://([^/:]+)")
    if not host then return false end
    host = host:lower()
    if host == "localhost" or host:match("^127%.") or host:match("^10%.")
       or host:match("^172%.1[6-9]%.") or host:match("^172%.2%d%.") or host:match("^172%.3[01]%.")
       or host:match("^192%.168%.") or host:match("^0%.") or host:match("^%[") then
        return false
    end
    return true
end

local function get_base()
    local b = cv_api_base and cv_api_base:GetString() or ETR_API_BASE
    b = (b or ""):gsub("/+$", "")
    if not validate_base_url(b) then
        log("Invalid API base URL, using default")
        return ETR_API_BASE
    end
    return b
end

local function get_key()
    return (cv_apikey and cv_apikey:GetString() or "") or ""
end

local function api_headers(key, extra)
    local h = {
        ["X-API-Key"] = key,
        ["Authorization"] = "Bearer " .. key,
        ["X-API-Version"] = "3",
    }
    if type(extra) == "table" then for k, v in pairs(extra) do h[k] = v end end
    return h
end

local function parse_rate_headers(headers)
    if type(headers) ~= "table" then return end
    for k, v in pairs(headers) do
        local lk = type(k) == "string" and k:lower() or ""
        if lk == "x-ratelimit-remaining" then
            etr_rate.remaining = tonumber(v)
        elseif lk == "x-ratelimit-reset" then
            local sec = tonumber(v)
            if sec then etr_rate.reset_at = CurTime() + sec end
        end
    end
end

local function rate_limited()
    if CurTime() < etr_rate.backoff_until then return true end
    if etr_rate.remaining ~= nil and etr_rate.remaining <= 1 and CurTime() < etr_rate.reset_at then
        return true
    end
    return false
end

local function apply_rate_backoff(code)
    if code == 429 then
        etr_consecutive_429 = etr_consecutive_429 + 1
        local delay = math.min(60 * math.pow(2, etr_consecutive_429 - 1), 900)
        etr_rate.backoff_until = math.max(etr_rate.backoff_until, CurTime() + delay)
        log("Rate limited, backoff " .. math.floor(delay) .. "s (x" .. etr_consecutive_429 .. ")")
    end
end

local function reset_backoff()
    etr_consecutive_429 = 0
end

local function log_api_error(code, body, headers)
    parse_rate_headers(headers)
    apply_rate_backoff(code)
    etr_stats.api_errors = etr_stats.api_errors + 1
    if not body or body == "" then log("API " .. tostring(code)) return end
    local ok, data = pcall(util.JSONToTable, body)
    if ok and data then
        local err = data.error or data.code or "error"
        local msg = data.message or ""
        local rid = data.request_id
        local parts = "API " .. tostring(code) .. " " .. tostring(err)
        if msg ~= "" then parts = parts .. ": " .. msg:sub(1, 120) end
        if rid then parts = parts .. " [" .. tostring(rid):sub(1, 36) .. "]" end
        log(parts)
    else
        log("API " .. tostring(code) .. ": " .. tostring(body):sub(1, 150))
    end
end

local function valid_steamid64(sid)
    if type(sid) ~= "string" then return false end
    sid = string.Trim(sid)
    if #sid < STEAMID64_LEN then return false end
    sid = sid:sub(1, STEAMID64_LEN)
    if not sid:match("^%d+$") then return false end
    return sid ~= "0" and sid >= STEAMID64_MIN
end

local function steamid64_string(val)
    if val == nil then return nil end
    if type(val) == "number" then val = string.format("%.0f", val) else val = type(val) == "string" and string.Trim(tostring(val)) or nil end
    if not val or #val < STEAMID64_LEN then return nil end
    val = val:sub(1, STEAMID64_LEN)
    return valid_steamid64(val) and val or nil
end

local function steamid_for_api(steamid)
    if steamid == nil then return nil end
    local s = type(steamid) == "number" and string.format("%.0f", steamid) or (type(steamid) == "string" and string.Trim(steamid) or nil)
    if not s or s == "" then return nil end
    if #s > 64 then return nil end
    if not s:match("^[%w:_%[%]]+$") then return nil end
    return s
end

local function to_steamid64(steamid)
    if steamid == nil then return nil end
    if type(steamid) == "number" then local s = steamid64_string(steamid); if s then return s end end
    if type(steamid) ~= "string" then return nil end
    steamid = string.Trim(steamid)
    if steamid:find("^%d+$") and #steamid >= STEAMID64_LEN and valid_steamid64(steamid) then return steamid:sub(1, STEAMID64_LEN) end
    if util.SteamIDTo64 then
        local ok, out = pcall(util.SteamIDTo64, steamid)
        if ok and out and out ~= "0" then
            out = type(out) == "string" and out or (type(out) == "number" and string.format("%.0f", out) or nil)
            return out and valid_steamid64(out) and out:sub(1, STEAMID64_LEN) or nil
        end
    end
    return nil
end

local function load_whitelist()
    etr_whitelist = {}
    if not file.Exists(WHITELIST_FILE, "DATA") then return end
    local content = file.Read(WHITELIST_FILE, "DATA")
    if not content then return end
    for line in content:gmatch("[^\r\n]+") do
        line = string.Trim(line)
        if line ~= "" and not line:match("^#") then
            local sid = to_steamid64(line) or line
            etr_whitelist[sid] = true
        end
    end
    log("Whitelist: " .. table.Count(etr_whitelist) .. " entries")
end

local function save_whitelist()
    local lines = {}
    for sid in pairs(etr_whitelist) do
        lines[#lines + 1] = sid
    end
    table.sort(lines)
    file.Write(WHITELIST_FILE, table.concat(lines, "\n"))
end

local function is_whitelisted(steamid)
    if table.Count(etr_whitelist) == 0 then return false end
    local sid64 = to_steamid64(steamid)
    if sid64 and etr_whitelist[sid64] then return true end
    local api_id = steamid_for_api(steamid)
    if api_id and etr_whitelist[api_id] then return true end
    return false
end

local function get_cached(steamid)
    local cache_key = to_steamid64(steamid) or steamid_for_api(steamid)
    if not cache_key then return nil end
    local cached = etr_cache[cache_key]
    local at = etr_cache_time[cache_key]
    local ttl = (cv_cache_ttl and cv_cache_ttl:GetInt()) or 3600
    if cached ~= nil and at and (CurTime() - at) < ttl then return cached end
    return nil
end

local function set_cache(key, banned)
    etr_cache[key] = banned
    etr_cache_time[key] = CurTime()
end

local function enforce_cache_limit()
    local count = 0
    for _ in pairs(etr_cache) do count = count + 1 end
    if count <= CACHE_MAX_SIZE then return end
    local oldest_key, oldest_time
    for sid, at in pairs(etr_cache_time) do
        if not oldest_time or at < oldest_time then
            oldest_time = at
            oldest_key = sid
        end
    end
    if oldest_key then
        etr_cache[oldest_key] = nil
        etr_cache_time[oldest_key] = nil
    end
end

local function clean_expired_cache()
    local ttl = (cv_cache_ttl and cv_cache_ttl:GetInt()) or 3600
    local t = CurTime()
    for sid, at in pairs(etr_cache_time) do
        if t - at > ttl then
            etr_cache[sid] = nil
            etr_cache_time[sid] = nil
        end
    end
end

local function server_update_payload()
    local hostname = GetHostName()
    if hostname == "" then hostname = "GMod Server" end
    local server_ip = game.GetIPAddress and game.GetIPAddress() or "0.0.0.0"
    if server_ip == "loopback" then server_ip = "0.0.0.0" end
    return { name = hostname, ip = server_ip, app_id = 4020, player_count = #player.GetAll(), max_players = game.MaxPlayers() }
end

local function register_server()
    local key = get_key()
    if key == "" then return end
    cv()
    local payload = server_update_payload()
    local base = get_base()
    if base == "" then return end
    local body = util.TableToJSON(payload)
    if not body or body == "" then return end
    local headers = api_headers(key, {
        ["Content-Type"] = "application/json",
        ["Content-Length"] = tostring(#body),
    })
    HTTP({
        url = base .. "/server/register",
        method = "POST",
        body = body,
        headers = headers,
        success = function(code, res_body, res_headers)
            parse_rate_headers(res_headers)
            if code >= 200 and code < 300 then
                reset_backoff()
                etr_registered = true
                etr_api_available = true
                if res_body and res_body ~= "" then
                    local ok, data = pcall(util.JSONToTable, res_body)
                    if ok and data and data.server_id then
                        etr_server_id = tostring(data.server_id)
                        log("Registered: " .. (data.name or payload.name) .. " (server_id=" .. etr_server_id .. ")")
                    else
                        log("Registered: " .. payload.name)
                    end
                else
                    log("Registered: " .. payload.name)
                end
            else
                log_api_error(code, res_body, res_headers)
            end
        end,
        failed = function(err)
            log("Register failed: " .. tostring(err))
        end,
    })
end

local function update_server()
    if not etr_server_id or etr_server_id == "" then return end
    local key = get_key()
    if key == "" then return end
    local base = get_base()
    if base == "" then return end
    local payload = server_update_payload()
    local body = util.TableToJSON(payload)
    if not body or body == "" then return end
    local headers = api_headers(key, {
        ["Content-Type"] = "application/json",
        ["Content-Length"] = tostring(#body),
    })
    HTTP({
        url = base .. "/server/" .. etr_server_id .. "/update",
        method = "POST",
        body = body,
        headers = headers,
        success = function(code, res_body, res_headers)
            parse_rate_headers(res_headers)
            if code >= 200 and code < 300 then
                reset_backoff()
            elseif res_body and res_body ~= "" then
                log_api_error(code, res_body, res_headers)
            end
        end,
        failed = function() end,
    })
end

local function check_key_info()
    local key = get_key()
    if key == "" then return end
    if rate_limited() then return end
    local base = get_base()
    if base == "" then return end
    http.Fetch(base .. "/key-info", function(body, size, resp_headers, code)
        parse_rate_headers(resp_headers)
        if code == 200 and body and body ~= "" then
            reset_backoff()
            local ok, data = pcall(util.JSONToTable, body)
            if ok and data then
                etr_key_info = data
                etr_api_available = true
                local perms = {}
                if data.verified then perms[#perms + 1] = "verified" end
                if data.can_add_users then perms[#perms + 1] = "can_add" end
                if data.can_check_list then perms[#perms + 1] = "can_list" end
                log("Key: " .. (#perms > 0 and table.concat(perms, ", ") or "basic"))
            end
        elseif code == 403 then
            log("Key invalid or expired")
            etr_api_available = false
        else
            log_api_error(code, body, resp_headers)
        end
    end, function(err)
        log("key-info failed: " .. tostring(err))
    end, api_headers(key))
end

local function parse_check_response(body, code)
    if code ~= 200 then return false end
    if not body or body == "" then return false end
    local ok, data = pcall(util.JSONToTable, body)
    if ok and data and data.status == true then return true end
    return false
end

local function check_player(steamid, callback)
    local api_id = steamid_for_api(steamid)
    if not callback or not api_id then if callback then callback(false) end return end
    local cache_key = to_steamid64(steamid) or api_id
    local key = get_key()
    if key == "" then callback(false) return end
    if rate_limited() then
        log("Rate limited, allowing player")
        callback(false)
        return
    end
    local base = get_base()
    if base == "" then callback(false) return end
    local url = base .. "/status/" .. api_id
    local headers = api_headers(key)
    etr_check_pending[cache_key] = true
    etr_stats.checks = etr_stats.checks + 1
    http.Fetch(url, function(body, size, resp_headers, code)
        etr_check_pending[cache_key] = nil
        parse_rate_headers(resp_headers)
        if code == 403 then
            etr_api_available = false
            log_api_error(code, body, resp_headers)
            callback(false)
            return
        end
        if code == 429 then
            apply_rate_backoff(code)
            etr_api_available = false
            log_api_error(code, body, resp_headers)
            callback(false)
            return
        end
        reset_backoff()
        etr_api_available = true
        local banned = parse_check_response(body or "", code)
        set_cache(cache_key, banned)
        enforce_cache_limit()
        hook.Run("ETR_PlayerChecked", cache_key, banned)
        callback(banned)
    end, function(err)
        etr_check_pending[cache_key] = nil
        etr_api_available = false
        etr_stats.api_errors = etr_stats.api_errors + 1
        log("Check failed: " .. tostring(err))
        callback(false)
    end, headers)
end

local function check_players_bulk(steam_ids, callback)
    if type(steam_ids) ~= "table" or #steam_ids == 0 then if callback then callback({}) end return end
    if #steam_ids > STATUS_BULK_MAX then
        local t = {}
        for i = 1, STATUS_BULK_MAX do t[i] = steam_ids[i] end
        steam_ids = t
    end
    local key = get_key()
    if key == "" then if callback then callback({}) end return end
    if rate_limited() then
        log("Rate limited, skipping bulk check")
        if callback then callback({}) end
        return
    end
    local base = get_base()
    if base == "" then if callback then callback({}) end return end
    local body = util.TableToJSON({ steam_ids = steam_ids })
    if not body then if callback then callback({}) end return end
    local headers = api_headers(key, {
        ["Content-Type"] = "application/json",
        ["Content-Length"] = tostring(#body),
    })
    etr_stats.checks = etr_stats.checks + #steam_ids
    HTTP({
        url = base .. "/status-bulk",
        method = "POST",
        body = body,
        headers = headers,
        success = function(code, res_body, res_headers)
            parse_rate_headers(res_headers)
            if code == 403 or code == 429 then
                etr_api_available = false
                apply_rate_backoff(code)
                log_api_error(code, res_body, res_headers)
            else
                reset_backoff()
                etr_api_available = true
            end
            local banned_map = {}
            if code == 200 and res_body and res_body ~= "" then
                local ok, data = pcall(util.JSONToTable, res_body)
                if ok and data then
                    local list = data.results or data.list or data
                    if type(list) == "table" then
                        for _, r in ipairs(list) do
                            if type(r) == "table" then
                                local sid = steamid64_string(r.steam_id or r.steamid)
                                if sid and r.status == true then banned_map[sid] = true end
                            end
                        end
                    end
                end
            end
            for _, sid in ipairs(steam_ids) do
                sid = steamid64_string(sid)
                if sid then
                    set_cache(sid, banned_map[sid] == true)
                    hook.Run("ETR_PlayerChecked", sid, banned_map[sid] == true)
                end
            end
            enforce_cache_limit()
            if callback then callback(banned_map) end
        end,
        failed = function(err)
            etr_api_available = false
            etr_stats.api_errors = etr_stats.api_errors + 1
            log("status-bulk failed: " .. tostring(err))
            if callback then callback({}) end
        end,
    })
end

local function queue_retry(entry)
    if #etr_retry_queue >= RETRY_QUEUE_MAX then return end
    etr_retry_queue[#etr_retry_queue + 1] = entry
    log("Queued " .. entry.type .. " for retry (" .. #etr_retry_queue .. " pending)")
end

local function do_vote(api_id, reason_id, comment_str, retry_entry)
    local key = get_key()
    if key == "" then return end
    if rate_limited() and not retry_entry then
        log("Rate limited, skipping vote")
        return
    end
    local base = get_base()
    if base == "" then return end
    local body = util.TableToJSON({
        vote_type = "for",
        reason_id = reason_id,
        comment = comment_str,
    })
    if not body then return end
    local headers = api_headers(key, {
        ["Content-Type"] = "application/json",
        ["Content-Length"] = tostring(#body),
    })
    HTTP({
        url = base .. "/vote/" .. api_id,
        method = "POST",
        body = body,
        headers = headers,
        success = function(code, res_body, res_headers)
            parse_rate_headers(res_headers)
            if code >= 200 and code < 300 then
                reset_backoff()
                etr_stats.votes = etr_stats.votes + 1
                if retry_entry then etr_stats.retries = etr_stats.retries + 1 end
                log("Vote submitted for " .. api_id)
            else
                log_api_error(code, res_body, res_headers)
                local entry = retry_entry or { type = "vote", steamid = api_id, reason_id = reason_id, comment = comment_str, attempts = 0 }
                entry.attempts = entry.attempts + 1
                if entry.attempts <= RETRY_MAX then
                    entry.next_at = CurTime() + 60 * math.pow(2, entry.attempts - 1)
                    queue_retry(entry)
                end
            end
        end,
        failed = function(err)
            etr_api_available = false
            etr_stats.api_errors = etr_stats.api_errors + 1
            log("Vote failed: " .. tostring(err))
            local entry = retry_entry or { type = "vote", steamid = api_id, reason_id = reason_id, comment = comment_str, attempts = 0 }
            entry.attempts = entry.attempts + 1
            if entry.attempts <= RETRY_MAX then
                entry.next_at = CurTime() + 60 * math.pow(2, entry.attempts - 1)
                queue_retry(entry)
            end
        end,
    })
end

local function do_feed(steam_ids, reason, comment, idempotency_key, retry_entry)
    if type(steam_ids) ~= "table" or #steam_ids == 0 then return end
    local key = get_key()
    if key == "" then return end
    if rate_limited() and not retry_entry then
        log("Rate limited, skipping feed")
        return
    end
    local base = get_base()
    if base == "" then return end
    local body = util.TableToJSON({
        steam_ids = steam_ids,
        reason = type(reason) == "string" and reason:sub(1, 512) or "Server ban list",
        comment = type(comment) == "string" and comment:sub(1, 500) or "",
    })
    if not body then return end
    local headers = api_headers(key, {
        ["Content-Type"] = "application/json",
        ["Content-Length"] = tostring(#body),
    })
    if type(idempotency_key) == "string" and idempotency_key ~= "" then
        headers["Idempotency-Key"] = idempotency_key:sub(1, 128)
    end
    HTTP({
        url = base .. "/feed",
        method = "POST",
        body = body,
        headers = headers,
        success = function(code, res_body, res_headers)
            parse_rate_headers(res_headers)
            if code >= 200 and code < 300 then
                reset_backoff()
                etr_stats.feeds = etr_stats.feeds + 1
                if retry_entry then etr_stats.retries = etr_stats.retries + 1 end
                if res_body and res_body ~= "" then
                    local ok, data = pcall(util.JSONToTable, res_body)
                    if ok and data then
                        log("Feed: created=" .. tostring(data.created or 0) ..
                            " skipped=" .. tostring(data.skipped or 0) ..
                            " invalid=" .. tostring(data.invalid or 0))
                    end
                end
            else
                log_api_error(code, res_body, res_headers)
                local entry = retry_entry or { type = "feed", steam_ids = steam_ids, reason = reason, comment = comment, idempotency_key = idempotency_key, attempts = 0 }
                entry.attempts = entry.attempts + 1
                if entry.attempts <= RETRY_MAX then
                    entry.next_at = CurTime() + 60 * math.pow(2, entry.attempts - 1)
                    queue_retry(entry)
                end
            end
        end,
        failed = function(err)
            etr_api_available = false
            etr_stats.api_errors = etr_stats.api_errors + 1
            log("Feed failed: " .. tostring(err))
            local entry = retry_entry or { type = "feed", steam_ids = steam_ids, reason = reason, comment = comment, idempotency_key = idempotency_key, attempts = 0 }
            entry.attempts = entry.attempts + 1
            if entry.attempts <= RETRY_MAX then
                entry.next_at = CurTime() + 60 * math.pow(2, entry.attempts - 1)
                queue_retry(entry)
            end
        end,
    })
end

local function process_retry_queue()
    if #etr_retry_queue == 0 then return end
    if not etr_api_available then return end
    if rate_limited() then return end
    local now = CurTime()
    for i = #etr_retry_queue, 1, -1 do
        local entry = etr_retry_queue[i]
        if entry.attempts > RETRY_MAX then
            table.remove(etr_retry_queue, i)
        elseif now >= (entry.next_at or 0) then
            table.remove(etr_retry_queue, i)
            if entry.type == "vote" then
                do_vote(entry.steamid, entry.reason_id, entry.comment, entry)
            elseif entry.type == "feed" then
                do_feed(entry.steam_ids, entry.reason, entry.comment, entry.idempotency_key, entry)
            end
            return
        end
    end
end

function ETR_SubmitBan(steamid, reason, duration_minutes)
    local api_id = to_steamid64(steamid) or steamid_for_api(steamid)
    if not api_id then return end
    local reason_id = cv_vote_reason_id and cv_vote_reason_id:GetInt() or 1
    local comment_str = type(reason) == "string" and reason:sub(1, 500) or "Server ban"
    if duration_minutes then
        comment_str = comment_str .. " (duration_min:" .. tostring(duration_minutes) .. ")"
    end
    do_vote(api_id, reason_id, comment_str, nil)
end

local function on_server_ban(steamid, reason, duration_minutes)
    if get_key() == "" then return end
    steamid = steamid_for_api(steamid)
    if not steamid then return end
    ETR_SubmitBan(steamid, reason or "Server ban", duration_minutes)
end

hook.Add("ETR_ReportBan", "ETR_Submit", function(steamid, reason, duration_minutes)
    on_server_ban(steamid, reason, duration_minutes)
end)

hook.Add("FAdmin_PlayerBanned", "ETR", function(ply, banner, reason, duration)
    if not IsValid(ply) then return end
    local sid = steamid_for_api(ply:SteamID64())
    if sid then on_server_ban(sid, reason, duration and (duration / 60) or nil) end
end)

if rawget(_G, "ULib") and ULib.ban then
    hook.Add("ULibPlayerBanned", "ETR", function(steamid, time, reason)
        local sid = steamid_for_api(steamid)
        if sid then on_server_ban(sid, reason, time and (time / 60) or nil) end
    end)
end

if rawget(_G, "sam") then
    hook.Add("sam.player.banned", "ETR", function(caller, steamid, duration, reason)
        local sid = steamid_for_api(steamid)
        if sid then on_server_ban(sid, reason, duration and (duration / 60) or nil) end
    end)
end

gameevent.Listen("server_addban")
hook.Add("server_addban", "ETR", function(data)
    if not data or not data.networkid then return end
    local sid = steamid_for_api(data.networkid)
    if not sid then return end
    local dur = data.duration
    on_server_ban(sid, data.name and ("Ban: " .. tostring(data.name)) or "Server ban", (type(dur) == "number" and dur > 0) and (dur / 60) or nil)
end)

local function same_player(steamid, ply)
    local p64 = steamid64_string(ply:SteamID64())
    if not p64 then return false end
    local k = to_steamid64(steamid) or steamid64_string(steamid)
    return k and k == p64
end

local function kick_banned_player(steamID64, source)
    local reject_msg = get_reject_msg()
    for _, p in ipairs(player.GetAll()) do
        if IsValid(p) and same_player(steamID64, p) then
            etr_stats.blocks = etr_stats.blocks + 1
            hook.Run("ETR_PlayerBlocked", steamID64, p:Nick(), source or "check")
            p:Kick(reject_msg)
            break
        end
    end
end

hook.Add("CheckPassword", "ETR", function(steamID64, ipAddress, svPassword, clPassword, name)
    cv()
    if not cv_enabled or cv_enabled:GetInt() == 0 then return end
    local steamid = steamid_for_api(steamID64)
    if not steamid then return end
    if is_whitelisted(steamID64) then
        etr_stats.whitelisted = etr_stats.whitelisted + 1
        log("Whitelisted: " .. steamid)
        return
    end
    local cached = get_cached(steamID64)
    if cached == true then
        etr_stats.blocks = etr_stats.blocks + 1
        hook.Run("ETR_PlayerBlocked", steamID64, name, "cache")
        log("Blocked: " .. steamid)
        return false, get_reject_msg()
    end
    if cached == false then return end
    local fail_open = (cv_fail_open and cv_fail_open:GetInt() ~= 0)
    local strict_first = (cv_strict_first and cv_strict_first:GetInt() ~= 0)
    if not etr_api_available and fail_open then
        check_player(steamID64, function(banned)
            if banned then kick_banned_player(steamID64, "async") end
        end)
        return
    end
    if strict_first then
        check_player(steamID64, function() end)
        return false, ETR_DEFAULT_STRICT_MSG
    end
    check_player(steamID64, function(banned)
        if not banned then return end
        kick_banned_player(steamID64, "async")
    end)
    if fail_open then return end
    return false, ETR_DEFAULT_STRICT_MSG
end)

local function collect_steam_ids_from_sources()
    local out = {}
    local seen = {}
    local function add(steamid)
        local id = steamid_for_api(steamid)
        if not id then return end
        local key = to_steamid64(steamid) or id
        if seen[key] then return end
        seen[key] = true
        out[#out + 1] = id
    end
    local custom = hook.Call("ETR_GetBansToPush")
    if type(custom) == "table" then
        for _, row in ipairs(custom) do
            local sid = (type(row) == "table" and (row.steamid64 or row.steamid)) or row
            add(sid)
        end
        if #out > 0 then return out, "custom" end
    end
    local fadmin = rawget(_G, "FAdmin")
    if fadmin and type(fadmin.BANS) == "table" then
        for steamid in pairs(fadmin.BANS) do add(steamid) end
        if #out > 0 then return out, "FAdmin" end
    end
    local ulib = rawget(_G, "ULib")
    if ulib and type(ulib.bans) == "table" then
        for steamid in pairs(ulib.bans) do add(steamid) end
        if #out > 0 then return out, "ULib" end
    end
    local sam = rawget(_G, "sam")
    if sam and sam.bans and type(sam.bans) == "table" then
        for steamid in pairs(sam.bans) do add(steamid) end
        if #out > 0 then return out, "SAM" end
    end
    return nil, nil
end

concommand.Add("etr_pushbans", function(ply, cmd, args)
    if IsValid(ply) and not ply:IsSuperAdmin() then return end
    cv()
    if get_key() == "" then
        print("[ETR] Set etr_apikey first.")
        return
    end
    local arg = args[1]
    if arg and arg ~= "" then
        local sid = steamid_for_api(arg)
        if sid then
            ETR_SubmitBan(sid, "Pushed from server", nil)
            log("Pushed: " .. arg)
        end
        return
    end
    local ids, source = collect_steam_ids_from_sources()
    if not ids or #ids == 0 then
        log("No ban source. Use etr_pushbans <steamid> or hook ETR_GetBansToPush.")
        return
    end
    for i = 1, #ids, FEED_MAX do
        local chunk = {}
        for j = i, math.min(i + FEED_MAX - 1, #ids) do
            chunk[#chunk + 1] = ids[j]
        end
        local idem = "etr_feed_" .. os.time() .. "_" .. math.ceil(i / FEED_MAX) .. "_" .. (chunk[1] or ""):sub(1, 40)
        do_feed(chunk, source and (source .. " ban list") or "Server ban list", "etr_pushbans", idem:sub(1, 128), nil)
    end
    log("Pushed " .. #ids .. " IDs via feed (" .. (source or "list") .. ").")
end, nil, "etr_pushbans [steamid]", 0)

concommand.Add("etr_keyinfo", function(ply)
    if IsValid(ply) and not ply:IsSuperAdmin() then return end
    if get_key() == "" then
        print("[ETR] Set etr_apikey first.")
        return
    end
    check_key_info()
    print("[ETR] Checking key info...")
end, nil, "Check ETR API key permissions", 0)

concommand.Add("etr_stats", function(ply)
    if IsValid(ply) and not ply:IsSuperAdmin() then return end
    print("[ETR] Session statistics:")
    print("  Checks: " .. etr_stats.checks)
    print("  Blocks: " .. etr_stats.blocks)
    print("  Whitelisted: " .. etr_stats.whitelisted)
    print("  Votes sent: " .. etr_stats.votes)
    print("  Feeds sent: " .. etr_stats.feeds)
    print("  API errors: " .. etr_stats.api_errors)
    print("  Retries: " .. etr_stats.retries)
    print("  Retry queue: " .. #etr_retry_queue)
    print("  Cache size: " .. table.Count(etr_cache))
    print("  Whitelist size: " .. table.Count(etr_whitelist))
    print("  API available: " .. tostring(etr_api_available))
    print("  Rate remaining: " .. tostring(etr_rate.remaining or "n/a"))
end, nil, "Show ETR session statistics", 0)

concommand.Add("etr_whitelist", function(ply, cmd, args)
    if IsValid(ply) and not ply:IsSuperAdmin() then return end
    local action = args[1]
    if action == "add" and args[2] then
        local sid = to_steamid64(args[2]) or steamid_for_api(args[2])
        if not sid then
            print("[ETR] Invalid Steam ID.")
            return
        end
        etr_whitelist[sid] = true
        save_whitelist()
        print("[ETR] Added " .. sid .. " to whitelist.")
    elseif action == "remove" and args[2] then
        local sid = to_steamid64(args[2]) or steamid_for_api(args[2])
        if not sid then
            print("[ETR] Invalid Steam ID.")
            return
        end
        etr_whitelist[sid] = nil
        save_whitelist()
        print("[ETR] Removed " .. sid .. " from whitelist.")
    elseif action == "list" then
        local count = 0
        for sid in pairs(etr_whitelist) do
            print("  " .. sid)
            count = count + 1
        end
        print("[ETR] Whitelist: " .. count .. " entries.")
    elseif action == "reload" then
        load_whitelist()
        print("[ETR] Whitelist reloaded.")
    else
        print("[ETR] Usage: etr_whitelist <add|remove|list|reload> [steamid]")
    end
end, nil, "Manage ETR whitelist", 0)

timer.Create("ETR_Refresh", 60, 0, function()
    cv()
    local key = get_key()
    if key ~= "" and not etr_registered then register_server() end
    clean_expired_cache()
    process_retry_queue()
end)

local etr_periodic_next = 0
timer.Create("ETR_PeriodicCheck", 1, 0, function()
    cv()
    local interval = (cv_periodic_interval and cv_periodic_interval:GetInt()) or 0
    if interval <= 0 or get_key() == "" then return end
    if not etr_api_available then return end
    if rate_limited() then return end
    local t = CurTime()
    if t < etr_periodic_next then return end
    etr_periodic_next = t + interval
    local to_check = {}
    for _, ply in ipairs(player.GetAll()) do
        if #to_check >= STATUS_BULK_MAX then break end
        if IsValid(ply) then
            local sid64 = steamid64_string(ply:SteamID64())
            if sid64 and not is_whitelisted(sid64) and get_cached(sid64) == nil then
                to_check[#to_check + 1] = sid64
            end
        end
    end
    if #to_check == 0 then return end
    check_players_bulk(to_check, function(banned_map)
        for _, ply in ipairs(player.GetAll()) do
            if IsValid(ply) then
                local sid64 = steamid64_string(ply:SteamID64())
                if sid64 and banned_map[sid64] then
                    etr_stats.blocks = etr_stats.blocks + 1
                    hook.Run("ETR_PlayerBlocked", sid64, ply:Nick(), "periodic")
                    ply:Kick(get_reject_msg())
                    log("Periodic kick: " .. sid64)
                end
            end
        end
    end)
end)

timer.Create("ETR_ServerUpdate", 1800, 0, function()
    cv()
    if etr_server_id and get_key() ~= "" then update_server() end
end)

cvars.AddChangeCallback("etr_apikey", function(cvname, old, new)
    if (old or "") == (new or "") then return end
    etr_registered = false
    etr_server_id = nil
    etr_key_info = nil
    if new and new ~= "" then
        timer.Simple(1, function()
            register_server()
            check_key_info()
        end)
    end
end, "ETR")

timer.Simple(2, function()
    cv()
    load_whitelist()
    if get_key() ~= "" then
        register_server()
        check_key_info()
    end
end)

log("ETR loaded.")

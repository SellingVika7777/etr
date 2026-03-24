-- ETR (Eblan Trouble Register) server addon. SellingVika. https://sellingvika.party/etr
if not SERVER then return end

local ETR_VERSION = "2.0.0"
local ETR_API_BASE = "https://sellingvika.party/etr/v3"
local ETR_DEFAULT_REJECT_MSG = "You are blocked by ETR (Eblan Trouble Register).\nMore info: https://sellingvika.party/etr"
local ETR_DEFAULT_STRICT_MSG = "[ETR] Please reconnect in 15 seconds."
local ETR_UA = "ETR-GModAddon/" .. ETR_VERSION .. " (Garry's Mod)"
local STEAMID64_LEN = 17
local STEAMID64_MIN = "76561197960265728"
local STATUS_BULK_MAX = 100
local ADD_BULK_MAX = 200
local CACHE_MAX_SIZE = 10000
local RETRY_MAX = 3
local RETRY_QUEUE_MAX = 50
local WHITELIST_FILE = "etr_whitelist.txt"
local CREDS_FILE = "etr_credentials.json"
local BATCH_INTERVAL = 3
local DEFAULT_HB_INTERVAL = 10800

local function hex2bin(hex)
    return (hex:gsub("..", function(cc) return string.char(tonumber(cc, 16)) end))
end

local function hmac_sha256(key, msg)
    if not util.SHA256 then return "" end
    local BS = 64
    if #key > BS then key = hex2bin(util.SHA256(key)) end
    key = key .. string.rep("\0", BS - #key)
    local ipad, opad = {}, {}
    for i = 1, BS do
        local b = string.byte(key, i)
        ipad[i] = string.char(bit.bxor(b, 0x36))
        opad[i] = string.char(bit.bxor(b, 0x5C))
    end
    local ip = table.concat(ipad)
    local op = table.concat(opad)
    local inner = hex2bin(util.SHA256(ip .. msg))
    return util.SHA256(op .. inner)
end

CreateConVar("etr_apikey", "", FCVAR_PROTECTED + FCVAR_NOTIFY, "", 0, 0)
CreateConVar("etr_api_secret", "", FCVAR_PROTECTED, "", 0, 0)
CreateConVar("etr_setup_token", "", FCVAR_PROTECTED, "", 0, 0)
CreateConVar("etr_enabled", "1", FCVAR_ARCHIVE, "", 0, 1)
CreateConVar("etr_api_base", ETR_API_BASE, FCVAR_ARCHIVE, "", 0, 0)
CreateConVar("etr_debug", "0", FCVAR_ARCHIVE, "", 0, 1)
CreateConVar("etr_cache_ttl", "3600", FCVAR_ARCHIVE, "", 60, 86400)
CreateConVar("etr_fail_open", "1", FCVAR_ARCHIVE, "", 0, 1)
CreateConVar("etr_periodic_interval", "600", FCVAR_ARCHIVE, "", 0, 3600)
CreateConVar("etr_strict_first", "0", FCVAR_ARCHIVE, "", 0, 1)
CreateConVar("etr_vote_reason_id", "1", FCVAR_ARCHIVE, "", 1, 100)
CreateConVar("etr_kick_message", "", FCVAR_ARCHIVE, "", 0, 0)

local cv = {}
local function refresh_cv()
    cv.apikey = GetConVar("etr_apikey")
    cv.secret = GetConVar("etr_api_secret")
    cv.setup_token = GetConVar("etr_setup_token")
    cv.enabled = GetConVar("etr_enabled")
    cv.api_base = GetConVar("etr_api_base")
    cv.debug = GetConVar("etr_debug")
    cv.cache_ttl = GetConVar("etr_cache_ttl")
    cv.fail_open = GetConVar("etr_fail_open")
    cv.periodic = GetConVar("etr_periodic_interval")
    cv.strict = GetConVar("etr_strict_first")
    cv.reason_id = GetConVar("etr_vote_reason_id")
    cv.kick_msg = GetConVar("etr_kick_message")
end
refresh_cv()

local state = {
    registered = false,
    server_id = nil,
    api_available = true,
    key_info = nil,
    cache = {},
    cache_time = {},
    pending = {},
    whitelist = {},
    retry_queue = {},
    batch_queue = {},
    consecutive_429 = 0,
    nonce_counter = 0,
    hb_interval = DEFAULT_HB_INTERVAL,
    hb_next = 0,
    server_time_offset = 0,
}

local rate = {
    remaining = nil,
    reset_at = 0,
    backoff_until = 0,
    minute_remaining = nil,
    minute_limit = nil,
    daily_remaining = nil,
    daily_limit = nil,
}

local stats = {
    checks = 0,
    blocks = 0,
    api_errors = 0,
    votes = 0,
    adds = 0,
    retries = 0,
    whitelisted = 0,
    heartbeats = 0,
}

local function log(msg)
    if not cv.debug or cv.debug:GetInt() == 0 then return end
    print("[ETR] " .. tostring(msg))
end

local function log_always(msg)
    print("[ETR] " .. tostring(msg))
end

local function get_reject_msg()
    local custom = cv.kick_msg and cv.kick_msg:GetString() or ""
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
    local b = cv.api_base and cv.api_base:GetString() or ETR_API_BASE
    b = (b or ""):gsub("/+$", "")
    if not validate_base_url(b) then
        log("Invalid API base URL, using default")
        return ETR_API_BASE
    end
    return b
end

local function get_key()
    return (cv.apikey and cv.apikey:GetString() or "")
end

local function get_secret()
    return (cv.secret and cv.secret:GetString() or "")
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

local function save_credentials(api_key, api_secret, server_id)
    local data = util.TableToJSON({ api_key = api_key, api_secret = api_secret, server_id = server_id })
    if data then
        file.CreateDir("etr")
        file.Write("etr/" .. CREDS_FILE, data)
        log("Credentials saved")
    end
end

local function load_credentials()
    local path = "etr/" .. CREDS_FILE
    if not file.Exists(path, "DATA") then return nil end
    local content = file.Read(path, "DATA")
    if not content or content == "" then return nil end
    local ok, data = pcall(util.JSONToTable, content)
    if not ok or not data then return nil end
    return data
end

local function init_credentials()
    local key = get_key()
    local secret = get_secret()
    if key ~= "" and secret ~= "" then return true end
    local creds = load_credentials()
    if not creds then return key ~= "" end
    if key == "" and creds.api_key and creds.api_key ~= "" then
        RunConsoleCommand("etr_apikey", creds.api_key)
        log("Loaded API key from credentials file")
    end
    if secret == "" and creds.api_secret and creds.api_secret ~= "" then
        RunConsoleCommand("etr_api_secret", creds.api_secret)
        log("Loaded API secret from credentials file")
    end
    if creds.server_id then state.server_id = tostring(creds.server_id) end
    return true
end

local function generate_nonce()
    state.nonce_counter = state.nonce_counter + 1
    return string.format("%d_%d_%06d", os.time(), state.nonce_counter, math.random(0, 999999))
end

local function get_timestamp()
    return tostring(os.time() + math.floor(state.server_time_offset))
end

local function url_path(full_url)
    return full_url:match("^https?://[^/]+(/.*)$") or "/"
end

local function parse_rate_headers(headers)
    if type(headers) ~= "table" then return end
    for k, v in pairs(headers) do
        local lk = type(k) == "string" and k:lower() or ""
        if lk == "x-ratelimit-remaining" then
            rate.daily_remaining = tonumber(v)
        elseif lk == "x-ratelimit-limit" then
            rate.daily_limit = tonumber(v)
        elseif lk == "x-ratelimit-reset" then
            local sec = tonumber(v)
            if sec then rate.reset_at = sec end
        elseif lk == "x-ratelimit-minute-remaining" then
            rate.minute_remaining = tonumber(v)
        elseif lk == "x-ratelimit-minute-limit" then
            rate.minute_limit = tonumber(v)
        elseif lk == "x-server-time" then
            local st = tonumber(v)
            if st then state.server_time_offset = st - os.time() end
        end
    end
end

local function rate_limited()
    if CurTime() < rate.backoff_until then return true end
    if rate.minute_remaining ~= nil and rate.minute_remaining <= 1 then return true end
    if rate.daily_remaining ~= nil and rate.daily_remaining <= 5 then return true end
    return false
end

local function apply_rate_backoff(code)
    if code == 429 then
        state.consecutive_429 = state.consecutive_429 + 1
        local delay = math.min(60 * math.pow(2, state.consecutive_429 - 1), 900)
        rate.backoff_until = math.max(rate.backoff_until, CurTime() + delay)
        log("Rate limited, backoff " .. math.floor(delay) .. "s (x" .. state.consecutive_429 .. ")")
    end
end

local function reset_backoff()
    state.consecutive_429 = 0
end

local function api_request(opts)
    local key = opts.key or get_key()
    local secret = opts.secret or get_secret()
    local base = get_base()
    local method = opts.method or "GET"
    local full_url = base .. (opts.path or "")
    local body_str = ""

    if opts.body then
        body_str = type(opts.body) == "string" and opts.body or util.TableToJSON(opts.body)
        if not body_str then body_str = "" end
    end

    local ts = get_timestamp()
    local nonce = generate_nonce()
    local path_for_sign = url_path(full_url)

    local headers = {
        ["User-Agent"] = ETR_UA,
        ["X-API-Version"] = "3",
        ["X-Timestamp"] = ts,
        ["X-Nonce"] = nonce,
    }

    if not opts.no_auth and key ~= "" then
        headers["X-API-Key"] = key
    end

    if opts.extra_headers then
        for k, v in pairs(opts.extra_headers) do headers[k] = v end
    end

    if secret ~= "" and util.SHA256 then
        local sign_msg = method .. ":" .. path_for_sign .. ":" .. body_str .. ":" .. ts
        headers["X-Signature"] = hmac_sha256(secret, sign_msg)
    end

    if body_str ~= "" then
        if util.SHA256 then
            headers["X-Body-SHA256"] = util.SHA256(body_str)
        end
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = tostring(#body_str)
    end

    local req = {
        url = full_url,
        method = method,
        headers = headers,
        success = function(code, res_body, res_headers)
            parse_rate_headers(res_headers)
            if code >= 200 and code < 300 then
                reset_backoff()
                state.api_available = true
            elseif code == 429 then
                apply_rate_backoff(code)
                state.api_available = false
                stats.api_errors = stats.api_errors + 1
            elseif code == 403 then
                state.api_available = false
                stats.api_errors = stats.api_errors + 1
            else
                if code >= 400 then stats.api_errors = stats.api_errors + 1 end
            end
            if opts.on_success then opts.on_success(code, res_body, res_headers) end
        end,
        failed = function(err)
            state.api_available = false
            stats.api_errors = stats.api_errors + 1
            if opts.on_fail then opts.on_fail(err) end
        end,
    }

    if body_str ~= "" then req.body = body_str end
    HTTP(req)
end

local function log_api_error(code, body, context)
    if not body or body == "" then log((context or "API") .. " " .. tostring(code)) return end
    local ok, data = pcall(util.JSONToTable, body)
    if ok and data then
        local err = data.error or "error"
        local msg = data.message or ""
        local rid = data.request_id
        local parts = (context or "API") .. " " .. tostring(code) .. " " .. tostring(err)
        if msg ~= "" then parts = parts .. ": " .. msg:sub(1, 120) end
        if rid then parts = parts .. " [" .. tostring(rid):sub(1, 36) .. "]" end
        log(parts)
    else
        log((context or "API") .. " " .. tostring(code) .. ": " .. tostring(body):sub(1, 150))
    end
end

local function get_cached(steamid)
    local k = to_steamid64(steamid) or steamid_for_api(steamid)
    if not k then return nil end
    local val = state.cache[k]
    local at = state.cache_time[k]
    local ttl = (cv.cache_ttl and cv.cache_ttl:GetInt()) or 3600
    if val ~= nil and at and (CurTime() - at) < ttl then return val end
    return nil
end

local function set_cache(k, banned)
    state.cache[k] = banned
    state.cache_time[k] = CurTime()
end

local function enforce_cache_limit()
    local count = 0
    for _ in pairs(state.cache) do count = count + 1 end
    if count <= CACHE_MAX_SIZE then return end
    local oldest_key, oldest_time
    for sid, at in pairs(state.cache_time) do
        if not oldest_time or at < oldest_time then oldest_time = at; oldest_key = sid end
    end
    if oldest_key then state.cache[oldest_key] = nil; state.cache_time[oldest_key] = nil end
end

local function clean_expired_cache()
    local ttl = (cv.cache_ttl and cv.cache_ttl:GetInt()) or 3600
    local t = CurTime()
    for sid, at in pairs(state.cache_time) do
        if t - at > ttl then state.cache[sid] = nil; state.cache_time[sid] = nil end
    end
end

local function load_whitelist()
    state.whitelist = {}
    if not file.Exists(WHITELIST_FILE, "DATA") then return end
    local content = file.Read(WHITELIST_FILE, "DATA")
    if not content then return end
    for line in content:gmatch("[^\r\n]+") do
        line = string.Trim(line)
        if line ~= "" and not line:match("^#") then
            local sid = to_steamid64(line) or line
            state.whitelist[sid] = true
        end
    end
    log("Whitelist: " .. table.Count(state.whitelist) .. " entries")
end

local function save_whitelist()
    local lines = {}
    for sid in pairs(state.whitelist) do lines[#lines + 1] = sid end
    table.sort(lines)
    file.Write(WHITELIST_FILE, table.concat(lines, "\n"))
end

local function is_whitelisted(steamid)
    if table.Count(state.whitelist) == 0 then return false end
    local sid64 = to_steamid64(steamid)
    if sid64 and state.whitelist[sid64] then return true end
    local api_id = steamid_for_api(steamid)
    if api_id and state.whitelist[api_id] then return true end
    return false
end

local function on_registered(api_key, api_secret, server_id, server_name)
    state.registered = true
    state.server_id = server_id and tostring(server_id) or nil
    state.api_available = true
    log_always("Registered: " .. (server_name or "server") .. (state.server_id and (" (id=" .. state.server_id .. ")") or ""))
    if api_key and api_key ~= "" then RunConsoleCommand("etr_apikey", api_key) end
    if api_secret and api_secret ~= "" then RunConsoleCommand("etr_api_secret", api_secret) end
    if api_key or api_secret then
        save_credentials(api_key or get_key(), api_secret or get_secret(), server_id)
    end
end

local function register_with_token()
    local token = cv.setup_token and cv.setup_token:GetString() or ""
    if token == "" then return false end
    local hostname = GetHostName()
    if hostname == "" then hostname = "GMod Server" end
    local server_ip = game.GetIPAddress and game.GetIPAddress() or "0.0.0.0"
    if server_ip == "loopback" then server_ip = "0.0.0.0" end
    api_request({
        method = "POST",
        path = "/servers/register",
        no_auth = true,
        body = { setup_token = token, name = hostname, ip = server_ip },
        extra_headers = { ["X-Setup-Token"] = token },
        on_success = function(code, body)
            if code >= 200 and code < 300 and body and body ~= "" then
                local ok, data = pcall(util.JSONToTable, body)
                if ok and data then
                    local sid = data.server and data.server.id or nil
                    local sname = data.server and data.server.name or hostname
                    on_registered(data.api_key, data.api_secret, sid, sname)
                    RunConsoleCommand("etr_setup_token", "")
                end
            else
                log_api_error(code, body, "Register")
            end
        end,
        on_fail = function(err) log("Registration failed: " .. tostring(err)) end,
    })
    return true
end

local function register_server()
    local key = get_key()
    if key == "" then
        register_with_token()
        return
    end
    state.registered = true
    state.api_available = true
    log("Using existing API key")
end

local send_heartbeat

send_heartbeat = function()
    if get_key() == "" then return end
    if rate_limited() then
        state.hb_next = CurTime() + 300
        return
    end
    api_request({
        method = "POST",
        path = "/heartbeat",
        on_success = function(code, body)
            if code >= 200 and code < 300 then
                stats.heartbeats = stats.heartbeats + 1
                if body and body ~= "" then
                    local ok, data = pcall(util.JSONToTable, body)
                    if ok and data and data.next_heartbeat_in then
                        state.hb_interval = tonumber(data.next_heartbeat_in) or DEFAULT_HB_INTERVAL
                        log("Heartbeat OK, next in " .. state.hb_interval .. "s")
                    end
                end
                state.hb_next = CurTime() + state.hb_interval
            else
                log_api_error(code, body, "Heartbeat")
                state.hb_next = CurTime() + 300
            end
        end,
        on_fail = function(err)
            log("Heartbeat failed: " .. tostring(err))
            state.hb_next = CurTime() + 300
        end,
    })
end

local function check_key_info()
    if get_key() == "" then return end
    if rate_limited() then return end
    api_request({
        method = "GET",
        path = "/key-info",
        on_success = function(code, body)
            if code == 200 and body and body ~= "" then
                local ok, data = pcall(util.JSONToTable, body)
                if ok and data then
                    state.key_info = data
                    local perms = {}
                    if data.verified then perms[#perms + 1] = "verified" end
                    if data.can_add_users then perms[#perms + 1] = "can_add" end
                    if data.can_check_list then perms[#perms + 1] = "can_list" end
                    log("Key: " .. (#perms > 0 and table.concat(perms, ", ") or "basic"))
                end
            else
                log_api_error(code, body, "KeyInfo")
            end
        end,
        on_fail = function(err) log("key-info failed: " .. tostring(err)) end,
    })
end

local function check_player(steamid, callback)
    local api_id = steamid_for_api(steamid)
    if not api_id then if callback then callback(false) end return end
    local cache_key = to_steamid64(steamid) or api_id
    if get_key() == "" then if callback then callback(false) end return end
    if rate_limited() then
        log("Rate limited, skipping check")
        if callback then callback(false) end
        return
    end
    state.pending[cache_key] = true
    stats.checks = stats.checks + 1
    api_request({
        method = "GET",
        path = "/status/" .. api_id,
        on_success = function(code, body)
            state.pending[cache_key] = nil
            local banned = false
            if code == 200 and body and body ~= "" then
                local ok, data = pcall(util.JSONToTable, body)
                if ok and data and data.status == true then banned = true end
            elseif code >= 400 then
                log_api_error(code, body, "Check")
            end
            set_cache(cache_key, banned)
            enforce_cache_limit()
            hook.Run("ETR_PlayerChecked", cache_key, banned)
            if callback then callback(banned) end
        end,
        on_fail = function(err)
            state.pending[cache_key] = nil
            log("Check failed: " .. tostring(err))
            if callback then callback(false) end
        end,
    })
end

local function check_players_bulk(steam_ids, callback)
    if type(steam_ids) ~= "table" or #steam_ids == 0 then if callback then callback({}) end return end
    if #steam_ids > STATUS_BULK_MAX then
        local t = {}
        for i = 1, STATUS_BULK_MAX do t[i] = steam_ids[i] end
        steam_ids = t
    end
    if get_key() == "" then if callback then callback({}) end return end
    if rate_limited() then
        log("Rate limited, skipping bulk check")
        if callback then callback({}) end
        return
    end
    stats.checks = stats.checks + #steam_ids
    api_request({
        method = "POST",
        path = "/status-bulk",
        body = { steam_ids = steam_ids },
        on_success = function(code, body)
            local banned_map = {}
            if code == 200 and body and body ~= "" then
                local ok, data = pcall(util.JSONToTable, body)
                if ok and data then
                    local list = data.results or data
                    if type(list) == "table" then
                        for _, r in ipairs(list) do
                            if type(r) == "table" then
                                local sid = steamid64_string(r.steam_id or r.steamid)
                                if sid and r.status == true then banned_map[sid] = true end
                            end
                        end
                    end
                end
            elseif code >= 400 then
                log_api_error(code, body, "BulkCheck")
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
        on_fail = function(err)
            log("status-bulk failed: " .. tostring(err))
            if callback then callback({}) end
        end,
    })
end

local function process_batch_queue()
    if #state.batch_queue == 0 then return end
    if rate_limited() then return end
    local batch = {}
    local callbacks = {}
    for _, entry in ipairs(state.batch_queue) do
        local sid = entry.steamid
        if sid and state.cache[sid] == nil then
            batch[#batch + 1] = sid
            if entry.callback then
                callbacks[sid] = callbacks[sid] or {}
                callbacks[sid][#callbacks[sid] + 1] = entry.callback
            end
        elseif sid and entry.callback then
            entry.callback(state.cache[sid] == true)
        end
    end
    state.batch_queue = {}
    if #batch == 0 then return end
    if #batch == 1 then
        check_player(batch[1], function(banned)
            local cbs = callbacks[batch[1]]
            if cbs then for _, cb in ipairs(cbs) do cb(banned) end end
        end)
        return
    end
    check_players_bulk(batch, function(banned_map)
        for sid, cbs in pairs(callbacks) do
            local banned = banned_map[sid] == true
            for _, cb in ipairs(cbs) do cb(banned) end
        end
    end)
end

local function queue_batch_check(steamid, callback)
    local sid = to_steamid64(steamid) or steamid_for_api(steamid)
    if not sid then if callback then callback(false) end return end
    state.batch_queue[#state.batch_queue + 1] = { steamid = sid, callback = callback }
end

local function queue_retry(entry)
    if #state.retry_queue >= RETRY_QUEUE_MAX then return end
    state.retry_queue[#state.retry_queue + 1] = entry
    log("Queued " .. (entry.type or "request") .. " for retry (" .. #state.retry_queue .. " pending)")
end

local function do_vote(api_id, reason_str, comment_str, retry_entry)
    if get_key() == "" then return end
    if rate_limited() and not retry_entry then return end
    api_request({
        method = "POST",
        path = "/vote/" .. api_id,
        body = {
            reason = type(reason_str) == "string" and reason_str:sub(1, 255) or "Server ban",
            comment = type(comment_str) == "string" and comment_str:sub(1, 500) or "",
        },
        on_success = function(code, body)
            if code >= 200 and code < 300 then
                stats.votes = stats.votes + 1
                if retry_entry then stats.retries = stats.retries + 1 end
                log("Vote submitted for " .. api_id)
                if body and body ~= "" then
                    local ok, data = pcall(util.JSONToTable, body)
                    if ok and data then
                        if data.vote_count and data.threshold then
                            log("Votes: " .. tostring(data.vote_count) .. "/" .. tostring(data.threshold))
                        end
                        if data.added_to_etr then log_always("Player " .. api_id .. " added to ETR") end
                    end
                end
            else
                log_api_error(code, body, "Vote")
                local entry = retry_entry or { type = "vote", steamid = api_id, reason = reason_str, comment = comment_str, attempts = 0 }
                entry.attempts = entry.attempts + 1
                if entry.attempts <= RETRY_MAX then
                    entry.next_at = CurTime() + 60 * math.pow(2, entry.attempts - 1)
                    queue_retry(entry)
                end
            end
        end,
        on_fail = function(err)
            log("Vote failed: " .. tostring(err))
            local entry = retry_entry or { type = "vote", steamid = api_id, reason = reason_str, comment = comment_str, attempts = 0 }
            entry.attempts = entry.attempts + 1
            if entry.attempts <= RETRY_MAX then
                entry.next_at = CurTime() + 60 * math.pow(2, entry.attempts - 1)
                queue_retry(entry)
            end
        end,
    })
end

local function do_add_bulk(steam_ids, reason, retry_entry)
    if type(steam_ids) ~= "table" or #steam_ids == 0 then return end
    if get_key() == "" then return end
    if rate_limited() and not retry_entry then return end
    api_request({
        method = "POST",
        path = "/add-bulk",
        body = {
            steam_ids = steam_ids,
            reason = type(reason) == "string" and reason:sub(1, 255) or "Server ban list",
        },
        on_success = function(code, body)
            if code >= 200 and code < 300 then
                stats.adds = stats.adds + 1
                if retry_entry then stats.retries = stats.retries + 1 end
                if body and body ~= "" then
                    local ok, data = pcall(util.JSONToTable, body)
                    if ok and data then
                        log("Add-bulk: added=" .. tostring(data.added and #data.added or 0) ..
                            " existing=" .. tostring(data.already_in_etr and #data.already_in_etr or 0) ..
                            " invalid=" .. tostring(data.invalid and #data.invalid or 0))
                    end
                end
            else
                log_api_error(code, body, "AddBulk")
                local entry = retry_entry or { type = "add_bulk", steam_ids = steam_ids, reason = reason, attempts = 0 }
                entry.attempts = entry.attempts + 1
                if entry.attempts <= RETRY_MAX then
                    entry.next_at = CurTime() + 60 * math.pow(2, entry.attempts - 1)
                    queue_retry(entry)
                end
            end
        end,
        on_fail = function(err)
            log("Add-bulk failed: " .. tostring(err))
            local entry = retry_entry or { type = "add_bulk", steam_ids = steam_ids, reason = reason, attempts = 0 }
            entry.attempts = entry.attempts + 1
            if entry.attempts <= RETRY_MAX then
                entry.next_at = CurTime() + 60 * math.pow(2, entry.attempts - 1)
                queue_retry(entry)
            end
        end,
    })
end

local function process_retry_queue()
    if #state.retry_queue == 0 then return end
    if not state.api_available then return end
    if rate_limited() then return end
    local now = CurTime()
    for i = #state.retry_queue, 1, -1 do
        local entry = state.retry_queue[i]
        if entry.attempts > RETRY_MAX then
            table.remove(state.retry_queue, i)
        elseif now >= (entry.next_at or 0) then
            table.remove(state.retry_queue, i)
            if entry.type == "vote" then
                do_vote(entry.steamid, entry.reason, entry.comment, entry)
            elseif entry.type == "add_bulk" then
                do_add_bulk(entry.steam_ids, entry.reason, entry)
            end
            return
        end
    end
end

function ETR_SubmitBan(steamid, reason, duration_minutes)
    local api_id = to_steamid64(steamid) or steamid_for_api(steamid)
    if not api_id then return end
    local reason_str = type(reason) == "string" and reason:sub(1, 255) or "Server ban"
    local comment_str = reason_str
    if duration_minutes then
        comment_str = comment_str .. " (duration: " .. tostring(duration_minutes) .. "min)"
    end
    do_vote(api_id, reason_str, comment_str, nil)
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
            stats.blocks = stats.blocks + 1
            hook.Run("ETR_PlayerBlocked", steamID64, p:Nick(), source or "check")
            p:Kick(reject_msg)
            break
        end
    end
end

hook.Add("CheckPassword", "ETR", function(steamID64, ipAddress, svPassword, clPassword, name)
    refresh_cv()
    if not cv.enabled or cv.enabled:GetInt() == 0 then return end
    local steamid = steamid_for_api(steamID64)
    if not steamid then return end
    if is_whitelisted(steamID64) then
        stats.whitelisted = stats.whitelisted + 1
        log("Whitelisted: " .. steamid)
        return
    end
    local cached = get_cached(steamID64)
    if cached == true then
        stats.blocks = stats.blocks + 1
        hook.Run("ETR_PlayerBlocked", steamID64, name, "cache")
        log("Blocked: " .. steamid)
        return false, get_reject_msg()
    end
    if cached == false then return end
    local fail_open = (cv.fail_open and cv.fail_open:GetInt() ~= 0)
    local strict_first = (cv.strict and cv.strict:GetInt() ~= 0)
    if strict_first then
        queue_batch_check(steamID64, function() end)
        return false, ETR_DEFAULT_STRICT_MSG
    end
    queue_batch_check(steamID64, function(banned)
        if banned then kick_banned_player(steamID64, "async") end
    end)
    if fail_open then return end
    return false, ETR_DEFAULT_STRICT_MSG
end)

local function collect_ban_ids()
    local out, seen = {}, {}
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
    local sam_mod = rawget(_G, "sam")
    if sam_mod and sam_mod.bans and type(sam_mod.bans) == "table" then
        for steamid in pairs(sam_mod.bans) do add(steamid) end
        if #out > 0 then return out, "SAM" end
    end
    return nil, nil
end

concommand.Add("etr_pushbans", function(ply, cmd, args)
    if IsValid(ply) and not ply:IsSuperAdmin() then return end
    refresh_cv()
    if get_key() == "" then print("[ETR] Set etr_apikey first.") return end
    local arg = args[1]
    if arg and arg ~= "" then
        local sid = steamid_for_api(arg)
        if sid then ETR_SubmitBan(sid, "Pushed from server", nil); log("Pushed: " .. arg) end
        return
    end
    local ids, source = collect_ban_ids()
    if not ids or #ids == 0 then
        log_always("No ban source found. Use etr_pushbans <steamid> or hook ETR_GetBansToPush.")
        return
    end
    local can_add = state.key_info and state.key_info.can_add_users
    if can_add then
        for i = 1, #ids, ADD_BULK_MAX do
            local chunk = {}
            for j = i, math.min(i + ADD_BULK_MAX - 1, #ids) do chunk[#chunk + 1] = ids[j] end
            do_add_bulk(chunk, source and (source .. " ban list") or "Server ban list", nil)
        end
    else
        for _, id in ipairs(ids) do
            do_vote(id, source and (source .. " ban") or "Server ban", "etr_pushbans", nil)
        end
    end
    log_always("Pushed " .. #ids .. " IDs via " .. (can_add and "add-bulk" or "vote") .. " (" .. (source or "list") .. ")")
end, nil, "Push bans to ETR", 0)

concommand.Add("etr_keyinfo", function(ply)
    if IsValid(ply) and not ply:IsSuperAdmin() then return end
    if get_key() == "" then print("[ETR] Set etr_apikey first.") return end
    check_key_info()
    print("[ETR] Checking key info...")
end, nil, "Check ETR API key permissions", 0)

concommand.Add("etr_stats", function(ply)
    if IsValid(ply) and not ply:IsSuperAdmin() then return end
    print("[ETR] Session statistics:")
    print("  Checks:        " .. stats.checks)
    print("  Blocks:        " .. stats.blocks)
    print("  Whitelisted:   " .. stats.whitelisted)
    print("  Votes sent:    " .. stats.votes)
    print("  Bulk adds:     " .. stats.adds)
    print("  Heartbeats:    " .. stats.heartbeats)
    print("  API errors:    " .. stats.api_errors)
    print("  Retries:       " .. stats.retries)
    print("  Retry queue:   " .. #state.retry_queue)
    print("  Batch queue:   " .. #state.batch_queue)
    print("  Cache size:    " .. table.Count(state.cache))
    print("  Whitelist:     " .. table.Count(state.whitelist))
    print("  API available: " .. tostring(state.api_available))
    print("  Rate daily:    " .. tostring(rate.daily_remaining or "n/a") .. "/" .. tostring(rate.daily_limit or "n/a"))
    print("  Rate minute:   " .. tostring(rate.minute_remaining or "n/a") .. "/" .. tostring(rate.minute_limit or "n/a"))
    print("  Heartbeat in:  " .. (state.hb_next > 0 and math.floor(math.max(0, state.hb_next - CurTime())) .. "s" or "pending"))
end, nil, "Show ETR session statistics", 0)

concommand.Add("etr_votings", function(ply)
    if IsValid(ply) and not ply:IsSuperAdmin() then return end
    if get_key() == "" then print("[ETR] Set etr_apikey first.") return end
    api_request({
        method = "GET",
        path = "/votings",
        on_success = function(code, body)
            if code == 200 and body and body ~= "" then
                local ok, data = pcall(util.JSONToTable, body)
                if ok and data and data.votings then
                    print("[ETR] Active votings (" .. tostring(#data.votings) .. "):")
                    for _, v in ipairs(data.votings) do
                        print("  " .. tostring(v.target_steam_id) ..
                            " votes=" .. tostring(v.vote_count) .. "/" .. tostring(v.threshold) ..
                            " (" .. tostring(v.progress or 0) .. "%)")
                    end
                    if data.threshold then print("  Threshold: " .. tostring(data.threshold) .. " of " .. tostring(data.verified_servers or "?") .. " servers") end
                else
                    print("[ETR] No active votings.")
                end
            else
                log_api_error(code, body, "Votings")
            end
        end,
        on_fail = function(err) print("[ETR] Failed: " .. tostring(err)) end,
    })
end, nil, "Show active ETR votings", 0)

concommand.Add("etr_add", function(ply, cmd, args)
    if IsValid(ply) and not ply:IsSuperAdmin() then return end
    if get_key() == "" then print("[ETR] Set etr_apikey first.") return end
    if not state.key_info or not state.key_info.can_add_users then
        print("[ETR] Key lacks can_add_users permission.")
        return
    end
    local sid = args[1] and steamid_for_api(args[1])
    if not sid then print("[ETR] Usage: etr_add <steamid> [reason]") return end
    local reason = args[2] or "Admin add"
    api_request({
        method = "POST",
        path = "/add/" .. sid,
        body = { reason = reason:sub(1, 255) },
        on_success = function(code, body)
            if code >= 200 and code < 300 then
                log_always("Added " .. sid .. " to ETR")
            else
                log_api_error(code, body, "Add")
            end
        end,
        on_fail = function(err) print("[ETR] Failed: " .. tostring(err)) end,
    })
end, nil, "Directly add Steam ID to ETR (admin key required)", 0)

concommand.Add("etr_whitelist", function(ply, cmd, args)
    if IsValid(ply) and not ply:IsSuperAdmin() then return end
    local action = args[1]
    if action == "add" and args[2] then
        local sid = to_steamid64(args[2]) or steamid_for_api(args[2])
        if not sid then print("[ETR] Invalid Steam ID.") return end
        state.whitelist[sid] = true
        save_whitelist()
        print("[ETR] Added " .. sid .. " to whitelist.")
    elseif action == "remove" and args[2] then
        local sid = to_steamid64(args[2]) or steamid_for_api(args[2])
        if not sid then print("[ETR] Invalid Steam ID.") return end
        state.whitelist[sid] = nil
        save_whitelist()
        print("[ETR] Removed " .. sid .. " from whitelist.")
    elseif action == "list" then
        local count = 0
        for sid in pairs(state.whitelist) do print("  " .. sid); count = count + 1 end
        print("[ETR] Whitelist: " .. count .. " entries.")
    elseif action == "reload" then
        load_whitelist()
        print("[ETR] Whitelist reloaded.")
    else
        print("[ETR] Usage: etr_whitelist <add|remove|list|reload> [steamid]")
    end
end, nil, "Manage ETR whitelist", 0)

timer.Create("ETR_Refresh", 60, 0, function()
    refresh_cv()
    if get_key() ~= "" and not state.registered then register_server() end
    clean_expired_cache()
    process_retry_queue()
end)

timer.Create("ETR_BatchCheck", BATCH_INTERVAL, 0, function()
    process_batch_queue()
end)

local etr_periodic_next = 0
timer.Create("ETR_PeriodicCheck", 30, 0, function()
    refresh_cv()
    local interval = (cv.periodic and cv.periodic:GetInt()) or 0
    if interval <= 0 or get_key() == "" then return end
    if not state.api_available then return end
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
                    stats.blocks = stats.blocks + 1
                    hook.Run("ETR_PlayerBlocked", sid64, ply:Nick(), "periodic")
                    ply:Kick(get_reject_msg())
                    log("Periodic kick: " .. sid64)
                end
            end
        end
    end)
end)

timer.Create("ETR_Heartbeat", 30, 0, function()
    refresh_cv()
    if get_key() == "" then return end
    if not state.registered then return end
    if CurTime() < state.hb_next then return end
    send_heartbeat()
end)

cvars.AddChangeCallback("etr_apikey", function(cvname, old, new)
    if (old or "") == (new or "") then return end
    state.registered = false
    state.server_id = nil
    state.key_info = nil
    state.hb_next = 0
    if new and new ~= "" then
        timer.Simple(1, function()
            register_server()
            check_key_info()
            send_heartbeat()
        end)
    end
end, "ETR")

timer.Simple(2, function()
    refresh_cv()
    load_whitelist()
    init_credentials()
    timer.Simple(1, function()
        refresh_cv()
        if get_key() ~= "" then
            register_server()
            check_key_info()
            send_heartbeat()
        elseif (cv.setup_token and cv.setup_token:GetString() or "") ~= "" then
            register_with_token()
        else
            log("No API key or setup token. Set etr_apikey or etr_setup_token.")
        end
    end)
end)

log("ETR v" .. ETR_VERSION .. " loaded.")

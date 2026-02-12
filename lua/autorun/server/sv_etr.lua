-- ETR (Eblan Trouble Register) server addon. SellingVika. https://sellingvika.party/etr
if not SERVER then return end

local ETR_API_BASE = "https://sellingvika.party/etr/v3"
local ETR_REJECT_MSG = "Вы заблокированы системой ETR (Eblan Trouble Register).\nПодробнее: https://sellingvika.party/etr"
local ETR_STRICT_MSG = "[ETR]. Подключитесь повторно через 15 секунд."
local STEAMID64_LEN = 17
local STEAMID64_MIN = "76561197960265728"

local cv_apikey, cv_enabled, cv_api_base, cv_debug
local cv_cache_ttl, cv_fail_open, cv_periodic_interval, cv_strict_first
local etr_registered = false
local etr_server_id = nil
local etr_api_available = true
local etr_cache = {}
local etr_cache_time = {}
local etr_check_pending = {}
local STATUS_BULK_MAX = 100

CreateConVar("etr_apikey", "", FCVAR_PROTECTED + FCVAR_NOTIFY, "", 0, 0)
CreateConVar("etr_enabled", "1", FCVAR_ARCHIVE, "", 0, 1)
CreateConVar("etr_api_base", ETR_API_BASE, FCVAR_ARCHIVE, "", 0, 0)
CreateConVar("etr_debug", "0", FCVAR_ARCHIVE, "", 0, 1)
CreateConVar("etr_cache_ttl", "3600", FCVAR_ARCHIVE, "", 60, 86400)
CreateConVar("etr_fail_open", "1", FCVAR_ARCHIVE, "", 0, 1)
CreateConVar("etr_periodic_interval", "600", FCVAR_ARCHIVE, "", 0, 3600)
CreateConVar("etr_strict_first", "0", FCVAR_ARCHIVE, "", 0, 1)

local function cv()
    cv_apikey = GetConVar("etr_apikey")
    cv_enabled = GetConVar("etr_enabled")
    cv_api_base = GetConVar("etr_api_base")
    cv_debug = GetConVar("etr_debug")
    cv_cache_ttl = GetConVar("etr_cache_ttl")
    cv_fail_open = GetConVar("etr_fail_open")
    cv_periodic_interval = GetConVar("etr_periodic_interval")
    cv_strict_first = GetConVar("etr_strict_first")
end
cv()

local function log(msg)
    if not cv_debug or cv_debug:GetInt() == 0 then return end
    print("[ETR] " .. tostring(msg))
end

local function api_headers(key, extra)
    local h = { ["X-API-Key"] = key, ["X-API-Version"] = "3" }
    if type(extra) == "table" then for k, v in pairs(extra) do h[k] = v end end
    return h
end

local function log_api_error(code, body)
    if not body or body == "" then log("API " .. tostring(code)) return end
    local ok, data = pcall(util.JSONToTable, body)
    if ok and data then
        local err = data.error or data.code or "error"
        local msg = data.message or ""
        log("API " .. tostring(code) .. " " .. tostring(err) .. (msg ~= "" and ": " .. msg:sub(1, 100) or ""))
    else
        log("API " .. tostring(code) .. ": " .. tostring(body):sub(1, 150))
    end
end

local function get_base()
    local b = cv_api_base and cv_api_base:GetString() or ETR_API_BASE
    return (b or ""):gsub("/+$", "")
end

local function get_key()
    return (cv_apikey and cv_apikey:GetString() or "") or ""
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
    return (s and s ~= "") and s or nil
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

local function server_update_payload()
    local hostname = GetHostName()
    if hostname == "" then hostname = "GMod Server" end
    local server_ip = game.GetIPAddress and game.GetIPAddress() or "0.0.0.0"
    if server_ip == "loopback" then server_ip = "0.0.0.0" end
    return { name = hostname, ip = server_ip, app_id = 4020 }
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
        success = function(code, res_body)
            if code >= 200 and code < 300 then
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
                log_api_error(code, res_body)
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
        success = function(code, res_body)
            if code ~= 200 and code ~= 201 and res_body and res_body ~= "" then
                log_api_error(code, res_body)
            end
        end,
        failed = function() end,
    })
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
    local base = get_base()
    if base == "" then callback(false) return end
    local url = base .. "/status/" .. api_id
    local headers = api_headers(key)
    etr_check_pending[cache_key] = true
    http.Fetch(url, function(body, size, respHeaders, code)
        etr_check_pending[cache_key] = nil
        if code == 403 or code == 429 then
            etr_api_available = false
            log_api_error(code, body)
            log("Failing open.")
        else
            etr_api_available = true
        end
        local banned = parse_check_response(body or "", code)
        local ttl = (cv_cache_ttl and cv_cache_ttl:GetInt()) or 3600
        etr_cache[cache_key] = banned
        etr_cache_time[cache_key] = CurTime()
        callback(banned)
    end, function(err)
        etr_check_pending[cache_key] = nil
        etr_api_available = false
        log("Check failed: " .. tostring(err))
        callback(false)
    end, headers)
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

local function check_players_bulk(steam_ids, callback)
    if type(steam_ids) ~= "table" or #steam_ids == 0 then if callback then callback({}) end return end
    if #steam_ids > STATUS_BULK_MAX then
        local t = {}
        for i = 1, STATUS_BULK_MAX do t[i] = steam_ids[i] end
        steam_ids = t
    end
    local key = get_key()
    if key == "" then if callback then callback({}) end return end
    local base = get_base()
    if base == "" then if callback then callback({}) end return end
    local body = util.TableToJSON({ steam_ids = steam_ids })
    if not body then if callback then callback({}) end return end
    local headers = api_headers(key, {
        ["Content-Type"] = "application/json",
        ["Content-Length"] = tostring(#body),
    })
    HTTP({
        url = base .. "/status-bulk",
        method = "POST",
        body = body,
        headers = headers,
        success = function(code, res_body)
            if code == 403 or code == 429 then
                etr_api_available = false
                log_api_error(code, res_body)
            else
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
            local ttl = (cv_cache_ttl and cv_cache_ttl:GetInt()) or 3600
            local now = CurTime()
            for _, sid in ipairs(steam_ids) do
                sid = steamid64_string(sid)
                if sid then
                    etr_cache[sid] = banned_map[sid] == true
                    etr_cache_time[sid] = now
                end
            end
            if callback then callback(banned_map) end
        end,
        failed = function(err)
            etr_api_available = false
            log("status-bulk failed: " .. tostring(err))
            if callback then callback({}) end
        end,
    })
end

local FEED_MAX = 200

local function send_feed(steam_ids, reason, comment, idempotency_key)
    if type(steam_ids) ~= "table" or #steam_ids == 0 then return end
    local key = get_key()
    if key == "" then return end
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
        success = function() end,
        failed = function()
            etr_api_available = false
        end,
    })
end

function ETR_SubmitBan(steamid, reason, duration_minutes)
    steamid = steamid_for_api(steamid)
    if not steamid then return end
    local key = get_key()
    if key == "" then return end
    local base = get_base()
    if base == "" then return end
    local reason_str = type(reason) == "string" and reason:sub(1, 512) or "Server ban"
    local body = util.TableToJSON({
        steam_id = steamid,
        vote_type = "for",
        reason = reason_str,
        comment = duration_minutes and ("duration_min:" .. tostring(duration_minutes)) or "",
    })
    if not body then return end
    local headers = api_headers(key, {
        ["Content-Type"] = "application/json",
        ["Content-Length"] = tostring(#body),
    })
    HTTP({
        url = base .. "/vote",
        method = "POST",
        body = body,
        headers = headers,
        success = function() end,
        failed = function()
            etr_api_available = false
        end,
    })
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

hook.Add("CheckPassword", "ETR", function(steamID64, ipAddress, svPassword, clPassword, name)
    cv()
    if not cv_enabled or cv_enabled:GetInt() == 0 then return end
    local steamid = steamid_for_api(steamID64)
    if not steamid then return end
    local cached = get_cached(steamID64)
    if cached == true then
        log("Blocked: " .. steamid)
        return false, ETR_REJECT_MSG
    end
    if cached == false then return end
    local fail_open = (cv_fail_open and cv_fail_open:GetInt() ~= 0)
    local strict_first = (cv_strict_first and cv_strict_first:GetInt() ~= 0)
    if not etr_api_available and fail_open then
        check_player(steamID64, function(banned)
            if banned then
                for _, p in ipairs(player.GetAll()) do
                    if IsValid(p) and same_player(steamID64, p) then p:Kick(ETR_REJECT_MSG) break end
                end
            end
        end)
        return
    end
    if strict_first then
        check_player(steamID64, function() end)
        return false, ETR_STRICT_MSG
    end
    check_player(steamID64, function(banned)
        if not banned then return end
        for _, p in ipairs(player.GetAll()) do
            if IsValid(p) and same_player(steamID64, p) then p:Kick(ETR_REJECT_MSG) break end
        end
    end)
    if fail_open then return end
    return false, ETR_STRICT_MSG
end)

timer.Create("ETR_Refresh", 60, 0, function()
    cv()
    local key = get_key()
    if key ~= "" and not etr_registered then register_server() end
    local ttl = (cv_cache_ttl and cv_cache_ttl:GetInt()) or 3600
    local t = CurTime()
    for sid, at in pairs(etr_cache_time) do
        if t - at > ttl then
            etr_cache[sid] = nil
            etr_cache_time[sid] = nil
        end
    end
end)

local etr_periodic_next = 0
timer.Create("ETR_PeriodicCheck", 1, 0, function()
    cv()
    local interval = (cv_periodic_interval and cv_periodic_interval:GetInt()) or 0
    if interval <= 0 or get_key() == "" then return end
    if not etr_api_available then return end
    local t = CurTime()
    if t < etr_periodic_next then return end
    etr_periodic_next = t + interval
    local to_check = {}
    for _, ply in ipairs(player.GetAll()) do
        if #to_check >= STATUS_BULK_MAX then break end
        if IsValid(ply) then
            local sid64 = steamid64_string(ply:SteamID64())
            if sid64 and get_cached(sid64) == nil then
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
                    ply:Kick(ETR_REJECT_MSG)
                    log("Periodic kick: " .. sid64)
                end
            end
        end
    end)
end)

cvars.AddChangeCallback("etr_apikey", function(_, old, new)
    if new and new ~= "" then
        etr_registered = false
        timer.Simple(1, register_server)
    end
end, "ETR")

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
        for steamid, _ in pairs(fadmin.BANS) do add(steamid) end
        if #out > 0 then return out, "FAdmin" end
    end
    local ulib = rawget(_G, "ULib")
    if ulib and type(ulib.bans) == "table" then
        for steamid, _ in pairs(ulib.bans) do add(steamid) end
        if #out > 0 then return out, "ULib" end
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
        send_feed(chunk, source and (source .. " ban list") or "Server ban list", "etr_pushbans", idem:sub(1, 128))
    end
    log("Pushed " .. #ids .. " IDs via feed (" .. (source or "list") .. ").")
end, nil, "etr_pushbans [steamid]", 0)

timer.Simple(2, function()
    cv()
    if get_key() ~= "" then register_server() end
end)

timer.Create("ETR_ServerUpdate", 1800, 0, function()
    cv()
    if etr_server_id and get_key() ~= "" then update_server() end
end)

cvars.AddChangeCallback("etr_apikey", function(cvname, old, new)
    if (old or "") ~= (new or "") then etr_server_id = nil end
end, "ETR")

log("ETR loaded.")

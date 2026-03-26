# ETR Addon for Garry's Mod

Connects your GMod server to **ETR (Eblan Trouble Register)** — a shared ban registry.

**Website:** [sellingvika.party/etr](https://sellingvika.party/etr) | **API Docs:** [sellingvika.party/wiki](https://sellingvika.party/wiki) | **GitHub:** [github.com/SellingVika7777/etr](https://github.com/SellingVika7777/etr)

---

## How It Works

1. **On player connect** the server checks the player's Steam ID against ETR. If banned — connection is rejected. Results are **cached** (default 1 hour).
2. **Connect batching** — multiple simultaneous connections are batched into a single `/status-bulk` API call to minimize request usage.
3. **Heartbeat** — the server sends periodic heartbeats to ETR. The API dynamically tells the addon when to send the next one (typically every few hours).
4. **Bans from your server** are reported to ETR: FAdmin, ULX, SAM, or engine bans automatically send a vote. The `etr_pushbans` command sends the entire ban list at once.
5. **HMAC-SHA256 security** — all API requests are signed with mandatory security headers (`X-Signature`, `X-Timestamp`, `X-Nonce`, `X-Body-SHA256`, `User-Agent`).

---

## Installation

### Option A: Setup Token (new servers)

1. Copy the addon to `garrysmod/addons/etr_addon/`
2. Register at [sellingvika.party](https://sellingvika.party/etr) and get a **setup token** from your dashboard
3. Add to `server.cfg`:
```
etr_setup_token "your_setup_token_here"
```
4. Restart the server. The addon will register, receive an API key and secret, and save them automatically. The setup token is consumed and cleared.

### Option B: Existing API Key

1. Copy the addon to `garrysmod/addons/etr_addon/`
2. Add to `server.cfg`:
```
etr_apikey "your_key_here"
etr_api_secret "your_secret_here"
```
3. Restart the server.

### Push existing bans (optional)

In server console (superadmin only):
```
etr_pushbans
```
Collects bans from FAdmin, ULib, SAM and pushes them. Uses `/add-bulk` if your key has `can_add_users` permission, otherwise `/vote` for each.

Single Steam ID:
```
etr_pushbans STEAM_0:0:12345678
```

---

## Configuration (ConVars)

All settings go in `garrysmod/cfg/server.cfg`.

| ConVar | Default | Description |
|--------|---------|-------------|
| `etr_apikey` | `""` | ETR API key. **Required** (or use `etr_setup_token`). |
| `etr_api_secret` | `""` | API secret for HMAC-SHA256 request signing. |
| `etr_setup_token` | `""` | One-time setup token for new server registration. Consumed on use. |
| `etr_enabled` | `1` | Enable player checking on connect. |
| `etr_api_base` | `https://sellingvika.party/etr/v3` | API base URL. HTTPS only, SSRF-protected. |
| `etr_debug` | `0` | `1` = print debug messages to server console. |
| `etr_cache_ttl` | `3600` | Cache duration in seconds (60–86400). |
| `etr_fail_open` | `1` | If API unavailable: `1` = allow players, `0` = block. |
| `etr_periodic_interval` | `600` | Recheck online players every N seconds. `0` = disabled. |
| `etr_strict_first` | `0` | `1` = block until API responds, `0` = allow and check in background. |
| `etr_vote_reason_id` | `1` | Numeric reason ID for vote endpoint (1–100). |
| `etr_kick_message` | `""` | Custom kick message. Empty = default English message. |

Example:
```
etr_apikey "your_key"
etr_api_secret "your_secret"
etr_enabled 1
etr_fail_open 1
etr_periodic_interval 600
etr_kick_message ""
```

---

## Commands

All commands require **superadmin** privileges.

| Command | Description |
|---------|-------------|
| `etr_pushbans` | Push all bans from FAdmin/ULib/SAM to ETR. Uses add-bulk or vote depending on key permissions. |
| `etr_pushbans <steamid>` | Push a single Steam ID as a vote. |
| `etr_keyinfo` | Check API key permissions and verification status. |
| `etr_stats` | Show session statistics: checks, blocks, errors, retries, cache size, rate limits, heartbeat status. |
| `etr_votings` | Show all active votings (players being voted on but not yet in ETR). |
| `etr_add <steamid> [reason]` | Directly add a player to ETR (requires `can_add_users` permission). |
| `etr_whitelist add <steamid>` | Add to local whitelist (skips ETR checks). |
| `etr_whitelist remove <steamid>` | Remove from whitelist. |
| `etr_whitelist list` | List all whitelisted Steam IDs. |
| `etr_whitelist reload` | Reload whitelist from file. |

---

## Admin Mod Integration

Automatic ban reporting for:

- **FAdmin** — `FAdmin_PlayerBanned` hook
- **ULX/ULib** — `ULibPlayerBanned` hook
- **SAM** — `sam.player.banned` hook
- **Engine bans** — `server_addban` game event

### Custom admin system

Report a ban manually:
```lua
hook.Run("ETR_ReportBan", steamID64, reason, duration_minutes)
-- or
ETR_SubmitBan(steamID64, reason, duration_minutes)
```

Provide a custom ban list for `etr_pushbans`:
```lua
hook.Add("ETR_GetBansToPush", "MyAddon", function()
    return {
        { steamid64 = "76561198...", reason = "Cheat" },
        { steamid = "STEAM_0:0:123", reason = "Ban from DB" },
    }
end)
```

---

## Hooks (for other addons)

| Hook | Arguments | Description |
|------|-----------|-------------|
| `ETR_PlayerChecked` | `steamid64, banned` | Fires after every status check. |
| `ETR_PlayerBlocked` | `steamid64, name, source` | Fires when a player is kicked. `source`: `"cache"`, `"async"`, `"periodic"`. |
| `ETR_ReportBan` | `steamid, reason, duration_minutes` | Call to report a ban to ETR. |
| `ETR_GetBansToPush` | *(none)* | Return a table of ban entries for `etr_pushbans`. |

Example:
```lua
hook.Add("ETR_PlayerBlocked", "MyDiscordBot", function(steamid64, name, source)
    print("[LOG] Blocked: " .. name .. " (" .. steamid64 .. ") via " .. source)
end)
```

---

## Credentials Storage

When registering via setup token, the addon saves the returned `api_key` and `api_secret` to `garrysmod/data/etr/etr_credentials.json`. On subsequent startups, credentials are loaded automatically from this file if ConVars are empty.

---

## Features

- **HMAC-SHA256 signing** — all requests include `X-Signature`, `X-Timestamp`, `X-Nonce`, `X-Body-SHA256` per API v3 spec.
- **Connect batching** — multiple player connections are batched into single `/status-bulk` calls (every 3 seconds) to save API quota.
- **Dynamic heartbeat** — API tells the addon exactly when to send the next heartbeat via `next_heartbeat_in`. No fixed-interval spam.
- **Setup token registration** — new `/servers/register` endpoint with one-time setup tokens. Credentials auto-saved.
- **Retry queue** — failed votes and bulk adds are queued (up to 50 items, 3 retries each) with exponential backoff.
- **Exponential backoff** — rate limit delays: 60s → 120s → 240s → ... up to 900s on repeated 429 responses.
- **Dual rate limit tracking** — both per-minute (`X-RateLimit-Minute-Remaining`) and daily (`X-RateLimit-Remaining`) limits tracked.
- **Server time sync** — `X-Server-Time` header used to correct timestamp drift for HMAC signatures.
- **Smart pushbans** — uses `/add-bulk` for admin keys (up to 200 IDs) or `/vote` for regular keys.
- **SSRF protection** — API base URL validated for HTTPS, blocked for localhost/internal ranges.
- **Cache limit** — max 10,000 entries with LRU eviction.
- **Input sanitization** — Steam IDs validated by format and length before API calls.
- **request_id logging** — API error responses include `request_id` for debugging.
- **Session statistics** — `etr_stats` shows checks, blocks, errors, retries, rate limits, heartbeat countdown.
- **Active votings** — `etr_votings` shows players being voted on with progress percentage.
- **Direct add** — `etr_add` for admin keys to bypass voting.

---

## API Endpoints Used

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/servers/register` | POST | Register server with setup token |
| `/heartbeat` | POST | Server heartbeat with dynamic interval |
| `/key-info` | GET | Validate API key permissions |
| `/status/{steamId}` | GET | Check single player status |
| `/status-bulk` | POST | Check up to 100 players at once |
| `/vote/{steamId}` | POST | Vote to add player to ETR |
| `/add/{steamId}` | POST | Directly add player (admin keys) |
| `/add-bulk` | POST | Bulk add up to 200 players (admin keys) |
| `/votings` | GET | List active votings |

Full API documentation: [sellingvika.party/wiki](https://sellingvika.party/wiki)

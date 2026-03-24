# ETR Addon for Garry's Mod

Connects your GMod server to **ETR (Eblan Trouble Register)** — a shared ban registry: [https://sellingvika.party/etr](https://sellingvika.party/etr).

---

## How It Works

1. **On player connect** the server checks the player's Steam ID against ETR. If the player is in the registry, the connection is rejected. Results are **cached** (default 1 hour).
2. **Server registers** with ETR via API key (hostname, IP, player count).
3. **Bans from your server** are reported to ETR: FAdmin, ULX, SAM, or engine bans automatically send a vote. The `etr_pushbans` command sends the entire ban list at once (feed).
4. **On startup** the addon validates the API key via `/key-info` and logs available permissions.

---

## Installation

### 1. Install the addon

Copy the addon folder to your GMod addons directory:

```
garrysmod/addons/etr_addon/
```

### 2. Get an API key

- Go to [https://sellingvika.party/etr](https://sellingvika.party/etr)
- Log in or register
- Create an API key in your dashboard

### 3. Set the key on your server

In `server.cfg`:

```
etr_apikey "your_key_here"
```

After a map restart the addon will register the server and start checking players.

### 4. (Optional) Push existing bans to ETR

In server console (superadmin only):

```
etr_pushbans
```

Collects bans from FAdmin, ULib, or SAM and sends them via feed. Single Steam ID:

```
etr_pushbans STEAM_0:0:12345678
```

---

## Configuration (ConVars)

| ConVar | Default | Description |
|--------|---------|-------------|
| `etr_apikey` | `""` | ETR API key. **Required.** |
| `etr_enabled` | `1` | Enable player checking on connect. |
| `etr_api_base` | `https://sellingvika.party/etr/v3` | API base URL. Only change for custom backends. Validated for HTTPS and no internal addresses. |
| `etr_debug` | `0` | `1` to print debug messages to server console. |
| `etr_cache_ttl` | `3600` | Cache duration in seconds (60–86400). |
| `etr_fail_open` | `1` | If API is unavailable: `1` = allow players, `0` = block. |
| `etr_periodic_interval` | `600` | Recheck interval for online players (seconds). `0` = disabled. |
| `etr_strict_first` | `0` | `1` = block on first connect until API responds, `0` = allow and check in background. |
| `etr_vote_reason_id` | `1` | Numeric reason ID for `/vote` endpoint (1–100). |
| `etr_kick_message` | `""` | Custom kick message. Empty uses the default English message. |

Example config:

```
etr_apikey "your_key"
etr_enabled 1
etr_fail_open 1
etr_periodic_interval 600
etr_vote_reason_id 1
etr_kick_message ""
```

---

## Commands

| Command | Description |
|---------|-------------|
| `etr_pushbans` | Push all bans from FAdmin/ULib/SAM to ETR via feed. Superadmin only. |
| `etr_pushbans <steamid>` | Push a single Steam ID as a vote. |
| `etr_keyinfo` | Check API key permissions. |
| `etr_stats` | Show session statistics (checks, blocks, errors, retries, cache/queue size). |
| `etr_whitelist add <steamid>` | Add a Steam ID to the local whitelist (skips ETR checks). |
| `etr_whitelist remove <steamid>` | Remove a Steam ID from the whitelist. |
| `etr_whitelist list` | List all whitelisted Steam IDs. |
| `etr_whitelist reload` | Reload whitelist from file. |

---

## Admin Mod Integration

Automatic ban reporting is supported for:

- **FAdmin** — `FAdmin_PlayerBanned` hook
- **ULX/ULib** — `ULibPlayerBanned` hook
- **SAM** — `sam.player.banned` hook
- **Engine bans** — `server_addban` game event

### Custom admin system

Report a ban manually:

```lua
hook.Run("ETR_ReportBan", steamID64, reason, duration_minutes)
```

or:

```lua
ETR_SubmitBan(steamID64, reason, duration_minutes)
```

The text reason goes into the `comment` field; the numeric `reason_id` comes from the `etr_vote_reason_id` ConVar.

To provide a custom ban list for `etr_pushbans`:

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
| `ETR_PlayerChecked` | `steamid64, banned` | Fired after every status check completes. |
| `ETR_PlayerBlocked` | `steamid64, name, source` | Fired when a player is kicked. `source`: `"cache"`, `"async"`, `"periodic"`. |
| `ETR_ReportBan` | `steamid, reason, duration_minutes` | Call this to report a ban to ETR. |
| `ETR_GetBansToPush` | *(none)* | Return a table of ban entries for `etr_pushbans`. |

---

## Whitelist

The whitelist is stored in `garrysmod/data/etr_whitelist.txt`, one Steam ID per line. Lines starting with `#` are ignored. Whitelisted players skip ETR checks entirely.

---

## Features

- **Retry queue** — failed votes and feeds are queued (up to 50 items, 3 retries each) and automatically resent when the API recovers.
- **Exponential backoff** — rate limit delays escalate: 60s, 120s, 240s... up to 15 minutes on repeated 429 responses.
- **Rate limit tracking** — `X-RateLimit-Remaining` and `X-RateLimit-Reset` headers are parsed from every response.
- **SSRF protection** — API base URL is validated for HTTPS and blocked for localhost/internal ranges.
- **Cache limit** — max 10,000 entries to prevent memory growth.
- **Input sanitization** — Steam IDs are validated by format and length before API calls.
- **request_id logging** — API error responses include the `request_id` for debugging with ETR developers.
- **Dual auth headers** — both `X-API-Key` and `Authorization: Bearer` are sent for compatibility.
- **Player count** — server update payload includes `player_count` and `max_players`.
- **Session statistics** — `etr_stats` command shows checks, blocks, errors, retries, cache and queue size.

API documentation: [ETR API Wiki](https://sellingvika.party/wiki).

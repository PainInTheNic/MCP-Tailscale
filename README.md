# tailscale-mcp-server

A Model Context Protocol (MCP) server for **controlling and managing Tailscale** from Claude.

It is **not** read-only. The headline capability is that Claude can **connect and disconnect
the host machine** from Tailscale — a local operation that goes through the `tailscale` CLI (the
REST API cannot start/stop a specific node). On top of that it exposes local host management and
comprehensive tailnet management via the Tailscale REST API.

Built for Windows first (verified against Tailscale CLI `1.102.4`); also runs on macOS (the Tailscale
app's bundled CLI is found automatically) and Linux — anywhere the CLI runs.

## Highlights

- **Connect / disconnect this host** — reconnect is a silent, flag-free `tailscale up`; login/expired
  keys return an `authURL` instead of hanging; success is confirmed by polling until `Running` *and*
  `Self.Online`. No elevation needed on Windows.
- **Two backends behind one facade** — the local CLI (all host control) and the REST API (tailnet
  management). The server starts and stays useful even with **no** API credentials.
- **Security-first** — every CLI call uses `execFile` (no shell) through a per-subcommand flag
  **allow-list** with single `--flag=value` tokens (no flag-smuggling, no generic passthrough);
  secrets are redacted from all output (tool text *and* `structuredContent`) bar the one-time secret
  a create call exists to return; tools that can cut connectivity, remove access, mint credentials
  or can't be undone require **client-enforced human approval**
  (`_meta["anthropic/requiresUserInteraction"]`), not a model-supplied flag.
- **48 tools** across three risk tiers (24 read, 16 write, 8 admin), plus MCP **resources** and
  **prompts**, and a `tailscale_server_info` capability catalog that explains why any tool is withheld.

See [`PLAN.md`](./PLAN.md) for the original design, the adversarial-review changelog, and the
planned per-tool inventory. What actually ships is the [Tools](#tools) list below; the 🔒 set and
annotations there (enforced in `src/meta/approval.ts` and each tool's registration) supersede
PLAN.md's narrower gating.

## Install & build

Requires Node.js ≥ 18 (developed on 24) and the Tailscale CLI installed on the host.

```bash
npm install
npm run build
```

## Register with Claude

### Windows

Claude Code:

```bash
claude mcp add tailscale -- node "C:\\Users\\Nic\\Documents\\Claude\\Code\\MCP-Tailscale\\dist\\index.js"
```

Or add to your MCP client config (Claude Desktop `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "tailscale": {
      "command": "node",
      "args": ["C:\\Users\\Nic\\Documents\\Claude\\Code\\MCP-Tailscale\\dist\\index.js"],
      "env": {
        "TAILSCALE_RISK_LEVEL": "write"
      }
    }
  }
}
```

> On Windows, launch via `node dist/index.js` (or `cmd /c npx …`) — `execFile` cannot spawn a bare
> `npx` `.cmd`. Put credentials in the `env` block above, **not** in a shell profile (a
> cmd-launched server won't see those).

### macOS

Claude Code, registered for your user (every project):

```bash
claude mcp add --scope user tailscale \
  --env TAILSCALE_RISK_LEVEL=write \
  --env TAILSCALE_CLI_PATH=/Applications/Tailscale.app/Contents/MacOS/Tailscale \
  -- /usr/local/bin/node /Users/nicpierce/Documents/Claude/Code/MCP-Tailscale/dist/index.js
```

(The server name goes before the `--env` flags: `--env` takes several values and would swallow it.)

Or the equivalent JSON (the `mcpServers` block of `~/.claude.json` for user scope, or Claude Desktop's
`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "tailscale": {
      "command": "/usr/local/bin/node",
      "args": ["/Users/nicpierce/Documents/Claude/Code/MCP-Tailscale/dist/index.js"],
      "env": {
        "TAILSCALE_RISK_LEVEL": "write",
        "TAILSCALE_CLI_PATH": "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
      }
    }
  }
}
```

> - Use an absolute `node` path (`which node`: `/usr/local/bin/node` for the nodejs.org installer,
>   `/opt/homebrew/bin/node` for Homebrew) — apps launched from the Dock don't inherit your shell `PATH`.
> - With the Tailscale app installed, use **its bundled CLI**: the app's network extension is this
>   Mac's node, so that CLI always matches it. The server searches it first, so `TAILSCALE_CLI_PATH`
>   is optional — set it to pin the choice when a Homebrew `tailscale` is also installed (that one
>   warns about a client/daemon version mismatch whenever the two drift).
> - Spawned without a terminal, the app's executable starts the GUI instead of acting as the CLI
>   unless `TAILSCALE_BE_CLI=true` is set. The server sets that for the CLI process automatically
>   (whatever the path's letter case, through a symlink, or when found on `PATH`), so you don't need
>   it in `env` — unless `TAILSCALE_CLI_PATH` points at a wrapper script around the app binary.

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `TAILSCALE_RISK_LEVEL` | `write` | `read` (read-only), `write` (adds host and tailnet changes — several destructive and 🔒-gated), `admin` (adds irreversible or tailnet-wide tools: logout, expire/delete device, ACL update, auth keys, tailnet settings, delete webhook). |
| `TAILSCALE_CLI_PATH` | auto | Path to the CLI. Otherwise searched in order — Windows: `C:\Program Files\Tailscale\tailscale.exe`; macOS: the Tailscale app's bundled CLI, then `/usr/bin`, `/usr/local/bin`, `/opt/homebrew/bin`; Linux: `/usr/bin`, `/usr/local/bin`, `/opt/homebrew/bin` — then `PATH`. |
| `TAILSCALE_AUTH_KEY_FILE` | — | Path to a file holding a tailnet auth key for headless first-login (passed as `file:<path>`; never in argv). |
| `TS_LOCAL_API` | `0` | Reserved for the optional LocalAPI fast path (Phase 3). |
| `TAILSCALE_OAUTH_CLIENT_ID` / `TAILSCALE_OAUTH_CLIENT_SECRET` | — | **Preferred** REST credentials (OAuth client-credentials). Both or neither. |
| `TAILSCALE_API_KEY` | — | Legacy static API access token (inherits the creator's full role). |
| `TAILSCALE_TAILNET` | `-` | Tailnet for REST calls; `-` = the credential's own tailnet. |
| `TAILSCALE_API_BASE_URL` | `https://api.tailscale.com` | Override (https or loopback only). |
| `TAILSCALE_LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` (stderr only). |

REST tools appear **only when credentials are configured**. Recommended OAuth client scopes, by the
`TAILSCALE_RISK_LEVEL` you run:

| Risk level | OAuth scopes |
|---|---|
| `read` | `all:read` |
| `write` | `all:read` + `devices:core` (authorize, rename, tags, key expiry), `devices:routes` (device routes), `dns` (DNS config), `users` (approve / suspend / restore), `webhooks` (create webhook) |
| `admin` | the `write` set + `policy_file` (ACL update), `auth_keys` (create / delete auth keys), `feature_settings` (tailnet settings). Expire / delete device and delete webhook are covered by `devices:core` and `webhooks`. |

Tailscale requires an OAuth client with the `devices:core` or `auth_keys` write scope to be assigned
tags, and it can only apply / mint keys for those tags. A legacy `TAILSCALE_API_KEY` carries its
creator's full role (no scoping). `tailscale_server_info` reports what's available and why.

## Tools

Reads are always available; host and tailnet changes need `TAILSCALE_RISK_LEVEL=write` (several of
them destructive and 🔒); irreversible or tailnet-wide tools need `admin`. 🔒 = requires interactive
human approval in the host (anything that can cut connectivity, remove access, redirect traffic or
tailnet events, mint a credential or one-time secret, or can't be undone).

| Risk level | Host (CLI) + `server_info` — no credentials needed | Tailnet (REST) | Total |
|---|---|---|---|
| `read` | 12 | 12 | 24 |
| `write` (adds) | 6 | 10 | 16 |
| `admin` (adds) | 1 | 7 | 8 |
| **All** | **19** | **29** | **48** |

All names carry the `tailscale_` prefix.

- **Host (CLI):** `status`, `get_prefs`, `connect`, `disconnect` 🔒, `set_prefs` 🔒, `set_exit_node` 🔒,
  `set_routes` 🔒, `list_exit_nodes`, `ping`, `netcheck`, `version`, `whois`, `whoami`, `dns_status`,
  `get_syspolicy`, `list_profiles`, `switch_profile` 🔒, `logout` 🔒 (admin), `server_info`.
- **Tailnet (REST):** devices (`list_devices`/`get_device`/`authorize_device` 🔒/`set_device_name`/
  `set_device_tags` 🔒/`get_device_routes`/`set_device_routes` 🔒/`set_device_key_expiry` 🔒/
  `expire_device_key` 🔒 (admin)/`delete_device` 🔒 (admin)), DNS (`get_dns_config`/`set_dns_config` 🔒),
  policy (`get_policy_file`/`validate_policy_file`/`update_policy_file` 🔒 (admin) with If-Match ETag),
  keys (`list_auth_keys`/`create_auth_key` 🔒 (admin)/`delete_auth_key` 🔒 (admin)), settings
  (`get_tailnet_settings`/`update_tailnet_settings` 🔒 (admin)), webhooks (`list_webhooks`/
  `create_webhook` 🔒/`delete_webhook` 🔒 (admin)), users (`list_users`/`get_user`/`approve_user`/
  `suspend_user` 🔒/`restore_user`), and `get_audit_log`.

Resources: `tailscale://status`, `tailscale://prefs`, `tailscale://devices`, `tailscale://acl`.
Prompts: `diagnose_connectivity`, `review_acl_change`.

## Development

```bash
npm run typecheck   # tsc --noEmit
npm test            # node --test (argv allow-list, redaction, status parsing, policy/config,
                    # binary resolution + CLI env, tool layer via an in-memory MCP client)
npm run inspect     # build + MCP Inspector
```

## Security notes

- `up`/`down`/`logout` affect the **whole machine's** Tailscale connection (all users), and require
  the server to run as the user who owns the Tailscale session.
- Device names, ACL comments, and other tailnet free-text are treated as **untrusted**; devices are
  addressed by stable id, and impactful actions require the human-approval gate.
- `logout` expires the node key (full re-auth needed); `disconnect` does not — they are distinct.
- One-time secrets are the deliberate exception to redaction: `create_auth_key` (the new key) and
  `create_webhook` (its signing secret) show that one value in full in that single result, with a
  warning; every other secret in it (OAuth secret, API key, access tokens) stays redacted, and the
  value is scrubbed from all later output.
- The spawned `tailscale` CLI never receives the REST credentials: `TAILSCALE_OAUTH_CLIENT_ID`,
  `TAILSCALE_OAUTH_CLIENT_SECRET` and `TAILSCALE_API_KEY` are stripped from its environment.

## License

MIT

# tailscale-mcp-server

A Model Context Protocol (MCP) server for **controlling and managing Tailscale** from Claude.

It is **not** read-only. The headline capability is that Claude can **connect and disconnect
the host machine** from Tailscale — a local operation that goes through the `tailscale` CLI (the
REST API cannot start/stop a specific node). On top of that it exposes local host management and
comprehensive tailnet management via the Tailscale REST API.

Built for Windows first (verified against Tailscale CLI `1.102.4`), works anywhere the CLI runs.

## Highlights

- **Connect / disconnect this host** — reconnect is a silent, flag-free `tailscale up`; login/expired
  keys return an `authURL` instead of hanging; success is confirmed by polling until `Running` *and*
  `Self.Online`. No elevation needed on Windows.
- **Two backends behind one facade** — the local CLI (all host control) and the REST API (tailnet
  management). The server starts and stays useful even with **no** API credentials.
- **Security-first** — every CLI call uses `execFile` (no shell) through a per-subcommand flag
  **allow-list** with single `--flag=value` tokens (no flag-smuggling, no generic passthrough);
  secrets are redacted from all output; high-impact/irreversible tools require **client-enforced
  human approval** (`_meta["anthropic/requiresUserInteraction"]`), not a model-supplied flag.
- **41 tools** across three risk tiers, plus MCP **resources** and **prompts**, and a
  `tailscale_server_info` capability catalog that explains why any tool is withheld.

See [`PLAN.md`](./PLAN.md) for the full design, the adversarial-review changelog, and the
per-tool inventory.

## Install & build

Requires Node.js ≥ 18 (developed on 24) and the Tailscale CLI installed on the host.

```bash
npm install
npm run build
```

## Register with Claude

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

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `TAILSCALE_RISK_LEVEL` | `write` | `read` (read-only), `write` (adds connect/disconnect/set), `admin` (adds destructive tools). |
| `TAILSCALE_CLI_PATH` | auto | Path to `tailscale`/`tailscale.exe` if not in the default location or PATH. |
| `TAILSCALE_AUTH_KEY_FILE` | — | Path to a file holding a tailnet auth key for headless first-login (passed as `file:<path>`; never in argv). |
| `TS_LOCAL_API` | `0` | Reserved for the optional LocalAPI fast path (Phase 3). |
| `TAILSCALE_OAUTH_CLIENT_ID` / `TAILSCALE_OAUTH_CLIENT_SECRET` | — | **Preferred** REST credentials (OAuth client-credentials). Both or neither. |
| `TAILSCALE_API_KEY` | — | Legacy static API access token (inherits the creator's full role). |
| `TAILSCALE_TAILNET` | `-` | Tailnet for REST calls; `-` = the credential's own tailnet. |
| `TAILSCALE_API_BASE_URL` | `https://api.tailscale.com` | Override (https or loopback only). |
| `TAILSCALE_LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` (stderr only). |

REST tools appear **only when credentials are configured**. Recommended minimal OAuth scopes:
`all:read` for read-only; add `devices:core`, `devices:routes`, `dns`, `policy_file`, `auth_keys`
per the tool tiers you use. `tailscale_server_info` reports what's available and why.

## Tools

Reads are always available; writes need `TAILSCALE_RISK_LEVEL=write`; destructive/admin tools need
`admin`. 🔒 = requires interactive human approval in the host.

- **Host (CLI):** `status`, `get_prefs`, `connect`, `disconnect` 🔒, `set_prefs`, `set_exit_node` 🔒,
  `set_routes` 🔒, `list_exit_nodes`, `ping`, `netcheck`, `version`, `whois`, `whoami`, `dns_status`,
  `get_syspolicy`, `list_profiles`, `switch_profile` 🔒, `logout` 🔒 (admin), `server_info`.
- **Tailnet (REST):** devices (`list`/`get`/`authorize`/`set_name`/`set_tags`/`get_routes`/`set_routes`/
  `expire_device_key` 🔒/`delete_device` 🔒), DNS (`get_dns_config`/`set_dns_config`), policy
  (`get_policy_file`/`validate_policy_file`/`update_policy_file` 🔒 with If-Match ETag), keys
  (`list_auth_keys`/`create_auth_key`/`delete_auth_key` 🔒), settings (`get`/`update`), webhooks
  (`list`/`create`/`delete` 🔒), users (`list`/`get`/`approve`/`suspend`/`restore`), and
  `get_audit_log`.

Resources: `tailscale://status`, `tailscale://prefs`, `tailscale://devices`, `tailscale://acl`.
Prompts: `diagnose_connectivity`, `review_acl_change`.

## Development

```bash
npm run typecheck   # tsc --noEmit
npm test            # node --test (argv allow-list, redaction, status parsing, policy/config)
npm run inspect     # build + MCP Inspector
```

## Security notes

- `up`/`down`/`logout` affect the **whole machine's** Tailscale connection (all users), and require
  the server to run as the user who owns the Tailscale session.
- Device names, ACL comments, and other tailnet free-text are treated as **untrusted**; devices are
  addressed by stable id, and impactful actions require the human-approval gate.
- `logout` expires the node key (full re-auth needed); `disconnect` does not — they are distinct.

## License

MIT

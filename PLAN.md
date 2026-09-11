# Tailscale MCP Server — Design & Implementation Plan

> Status: **implemented (P0–P2 + resources/prompts + tests)**; live-verified connect/disconnect on
> this host. This plan was produced by researching Tailscale's
> CLI (ground-truthed against the installed `tailscale.exe` 1.102.4 on this host) and REST
> API, studying two reference servers ([HexSleeves](https://github.com/HexSleeves/tailscale-mcp)
> and [YawLabs](https://github.com/YawLabs/tailscale-mcp)), then adversarially critiquing our
> own draft on three axes (coverage, security, agent-ergonomics). The "Adversarial fine-tuning"
> section records what those critiques changed.

## 1. Goal

A **read/write** Model Context Protocol server that lets Claude control and manage Tailscale.

- **Immediate must-work requirement:** Claude can **connect and disconnect this host** from
  Tailscale. This is a *local* operation — the REST API cannot start/stop a specific node — so
  it goes through the local `tailscale` CLI.
- **Secondary:** comprehensive **tailnet management** via the Tailscale REST API (devices, DNS,
  ACL policy, keys, settings, webhooks, users, audit logs).

Not a goal: being a thin 1:1 wrapper of every endpoint. Tools are discrete, single-purpose, and
accurately annotated so the host can reason about which are safe to auto-run.

## 2. Verified environment (ground truth)

| Fact | Value | Source |
|---|---|---|
| Tailscale CLI | `1.102.4` at `C:\Program Files\Tailscale\tailscale.exe`, on PATH | live probe |
| Current backend state | `Stopped` (HaveNodeKey=true, Self.Online=false, IPs present) | `status --json` |
| Tailnet | `tail6073a5.ts.net`, this node tagged `tag:view` | `status --json` |
| Node runtime | Node.js v24, npm 11 (Python absent) | live probe |
| Elevation for up/down/set | **None required on Windows** (`--operator` is Unix-only, absent here) | CLI `up --help` |
| `status` exit code | plain `status` exits **1** when stopped; `status --json` exits **0** always | live probe |
| `tailscale wait` | real subcommand ("wait for interface/IPs") | CLI `--help` |

**Stack decision:** TypeScript / Node (ESM), `@modelcontextprotocol/sdk@1.30.0`, `zod@^3.25`,
native `fetch`, native `child_process`. stdio transport only. (Python isn't installed; both
reference repos are TS; the MCP builder guide recommends TS.)

## 3. Architecture

One stdio server, `tailscale-mcp-server`, tools prefixed `tailscale_`, wrapping **two backends**
behind a single `TailscaleService` facade, plus a tiny meta layer.

```
                         ┌───────────────────────────┐
   MCP tools ──────────► │      TailscaleService     │  (facade + fallback routing)
   (registerTool)        └───────────┬───────────────┘
                                     │
                 ┌───────────────────┴────────────────────┐
                 ▼                                         ▼
        HOST backend (this machine)             REST backend (tailnet-wide)
        ─ CliExecutor (default)                 ─ TailscaleApiClient
          execFile, shell:false, argv[]           native fetch → api.tailscale.com/api/v2
          all host WRITES go here                 OAuth client-credentials (preferred)
        ─ LocalApiClient (opt-in, reads only)       or static API key; token cache;
          named pipe → tailscaled                   429 backoff; base-host pinned
```

- **CliExecutor** is the guaranteed path: `execFile(binaryPath, argvArray, {shell:false,
  windowsHide:true, timeout, maxBuffer})`. All host *writes* (`up`/`down`/`set`/`logout`) go
  through it. Reads use `--json` / `--format json` and are parsed. **Process-level timeout +
  SIGKILL** bounds every call (never the CLI `--timeout` flag), so a bare `up` can stay
  flag-free and can't hang the MCP call.
- **LocalApiClient** (opt-in via `TS_LOCAL_API=1`): named-pipe HTTP to `tailscaled` for
  sub-ms `status`/`prefs` reads; **reads only**; silently falls back to the CLI on any error.
  Deferred to a later phase — the CLI is sufficient for v1.
- **TailscaleApiClient**: `fetch` to `https://api.tailscale.com/api/v2`. `auth.ts` mints/caches
  a Bearer token (OAuth client-credentials preferred, static API key fallback). `client.ts`
  **pins the Authorization header to `api.tailscale.com`** (attached only when the resolved host
  matches; dropped on cross-origin redirect via `redirect: "manual"`), honours `429 Retry-After`
  with backoff+jitter, applies a per-request wall-clock budget.
- **Fail-safe startup:** the server starts even with **no** API credentials — host/CLI tools stay
  fully functional; API tools return a clear setup error. A half-configured OAuth pair is
  rejected by a zod `superRefine` at startup. This prevents Claude-host restart loops.
- **Golden rule:** nothing ever writes to **stdout** (that's the JSON-RPC channel). All logs go
  to **stderr** through a redacting logger.

## 4. Module layout

```
src/
  index.ts                 # shebang; build server + StdioServerTransport; main().catch. NEVER console.log
  server.ts                # McpServer factory + registerAllTools wiring
  config.ts                # env parse + zod validation (auth, tailnet, cli path, risk level, flags)
  logger.ts                # stderr logger; uses redact()
  meta/
    approval.ts            # FORCED_APPROVAL_TOOLS, LARGE_RESULT_TOOLS, buildToolMeta()
  backends/
    host/
      types.ts             # HostBackend interface (status/prefs/up/down/set/logout) — NO generic raw()
      binary-resolver.ts   # TAILSCALE_CLI_PATH → C:\Program Files\Tailscale\tailscale.exe → PATH
      cli-executor.ts      # execFile wrapper (shell:false, timeout+kill, maxBuffer, windowsHide)
      argv-allowlist.ts    # per-subcommand fixed flag whitelist; single --flag=value tokens; reject '-'-leading values
      status-parse.ts      # normalize status --json → typed state incl. daemon-unreachable & key-expiry
      local-api.ts         # (Phase 3) optional named-pipe read client
    api/
      client.ts            # fetch wrapper: base-host pin, manual redirect, 429 backoff, budget
      auth.ts              # OAuth client-credentials token cache | API key
      endpoints/*.ts       # thin typed callers (devices/dns/policy/keys/settings/webhooks/users/logs)
  service/
    tailscale-service.ts   # facade + fallback routing
  tools/
    index.ts               # registerAllTools(server, service, config) — filters by risk level, attaches _meta
    connect.ts             # P0: status, connect, disconnect, get_prefs
    host.ts                # P1: set_prefs, exit-node, ping, netcheck, version, whois, whoami, dns_status, syspolicy, switch, logout
    devices.ts dns.ts policy.ts keys.ts settings.ts webhooks.ts users.ts logs.ts   # P2 REST
    meta.ts                # server_info / capabilities catalog
  validation/
    schemas.ts             # shared zod: deviceId, CIDR, IPv4/6, ^tag:[a-z0-9-]+$, hostname/nickname, exit-node
    guards.ts              # confirm-flag + risk-level gate helpers
  util/ redact.ts errors.ts exec.ts
```

Conventions: server name `tailscale-mcp-server`; tools `tailscale_<verb>_<noun>` (snake_case).
The core host tools (`tailscale_status`, `tailscale_connect`, `tailscale_disconnect`) drop the
`_<noun>` — the noun is implicitly "this host".

## 5. Connect / Disconnect / Status flow (corrected)

**STATUS (`tailscale_status`, read):** run `status --json`, parse into a normalized state.
Never trust the exit code. Report a single, unambiguous state enum:

- `running` — `BackendState==="Running"` **and** `Self.Online===true` (fully connected & reachable)
- `running_local_only` — `Running` but `Self.Online` not yet true (settling; distinguishes "up
  locally" from "reachable")
- `stopped` — `BackendState==="Stopped"`
- `needs_login` — `NeedsLogin`, **or** `HaveNodeKey` but `Self.Expired`/past `KeyExpiry` (key
  expiry is routed here, **not** to bare-`up`)
- `starting` / `no_state`
- `daemon_unreachable` — pipe/connection error talking to `tailscaled` (service off) — a
  **first-class** state, distinct from stopped/needs_login, with remedy "start the Tailscale
  service / launch the app".

`structuredContent` always emits **both** `backendState` and `selfOnline` plus `tailscaleIPs`,
`currentTailnet`, `health[]`, and `authURL` when present. (IP presence alone ≠ connected.)

**CONNECT (`tailscale_connect`, write):** v1 is **connectivity-only** (no pref args — those live
in `set_prefs`, removing the connect/set_prefs ambiguity). Flow:
1. Read status.
2. `running` → return already-connected.
3. `stopped` + valid key (this host's case) → run **bare `tailscale up`** (no flags — passing any
   pref flag triggers the "complete set of settings" error; bare `up` just brings WireGuard online,
   silent, no browser).
4. `needs_login` / expired key → **do not** run bare `up`. If `TAILSCALE_AUTH_KEY_FILE` is set,
   run `up --auth-key file:<path>` (secret never in argv). Otherwise trigger login non-blocking and
   **poll `status --json` for the top-level `AuthURL`**, returning it immediately ("open this to
   finish login") — never block on a blocking `up --json`. SIGKILLing the `up` client does not
   abort the daemon-side pending login.
5. **Success detection:** run `tailscale wait` (bounded by execFile timeout), then poll
   `status --json` until `Self.Online===true` within a bounded window (~+15s). Return the final
   normalized state so "connected" means the same thing everywhere.

**DISCONNECT (`tailscale_disconnect`, write, forced-approval):** run `tailscale down` (no flags;
`--reason` only if policy requires). Poll `status --json` until `Stopped`, with an **explicit
timeout + max attempts**. Reversible via connect; **does not** expire the node key.

**LOGOUT (`tailscale_logout`, destructive, forced-approval, admin-gated):** `tailscale logout`
expires the node key → next connect needs full re-auth. Kept strictly separate from disconnect.

## 6. Security model

Layered defense; the mechanical baseline already beats both reference repos, and the critiques
closed the human-in-the-loop gaps.

1. **No shell, ever.** Every host call is `execFile(shell:false)` with an **argv array**. User
   input is never concatenated into a command line.
2. **Per-subcommand flag allow-list** (`argv-allowlist.ts`, the sole argv chokepoint). Value-
   bearing flags are emitted as a **single `--flag=value` token** (never two tokens, so a value
   can't be re-read as a flag); any bound value beginning with `-` is rejected. **No generic
   `raw()` passthrough** is ever exposed as a tool. A test feeds `-`/`--flag`-shaped values into
   every host tool and asserts rejection.
3. **Client-enforced approval (the real gate).** A required `confirm:true` *input* is **not** a
   gate — the model fills its own inputs. Instead a **narrow** `FORCED_APPROVAL_TOOLS` set carries
   `_meta["anthropic/requiresUserInteraction"]=true` (via `registerTool`; the legacy
   `server.tool()` API silently drops `_meta`), which forces the *host* to prompt a human and
   cannot be routed around. `confirm:true` is kept only as a secondary "did-you-mean-it".
   - **Forced-approval set:** `tailscale_disconnect`, `tailscale_logout`, `tailscale_set_exit_node`,
     `tailscale_set_routes`, `tailscale_switch_profile` (host, traffic-redirection/identity), plus
     REST `tailscale_delete_device`, `tailscale_expire_device_key`, `tailscale_delete_auth_key`,
     `tailscale_update_policy_file`, `tailscale_delete_webhook` (and `delete_user` when added).
   - Kept deliberately narrow so operators don't learn to click through it.
4. **Traffic-redirection is special-cased.** Setting an exit node silently routes *all* host
   traffic through another node (a full MITM); route/profile changes hijack connectivity or move
   tailnets. These are forced-approval **regardless of risk level**, and their tool results
   surface the *target node's identity* so a human approving can see where traffic will flow.
5. **Secret hygiene.** Credentials only via env or `file:` indirection — never in argv (process
   table) or tool inputs. `redact()` scrubs secrets by **exact-value match** (catches every
   encoding: form `client_secret=`, JSON, header, bare `tskey-*`) across **all** model-facing
   output — tool text, `structuredContent`, and error envelopes — not just logs. `create_auth_key`
   returns its one-time secret in the result but never to the debug log.
6. **REST anti-SSRF/exfil.** Authorization attached only when host `=== api.tailscale.com`;
   `redirect: "manual"`; base override allowed only for https/loopback (zod-enforced).
7. **Untrusted tool output.** Peer/device/ACL/DNS free-text (names, comments) is attacker-
   influenceable (other people's machines on the tailnet) → treated as untrusted data, delivered
   in delimited data regions, and **never** allowed to drive a privileged follow-up without the
   forced-approval gate. Devices are resolved by stable **id**, not by model-chosen name.
8. **Accurate annotations** so hosts can auto-allow safe ops: reads `readOnlyHint:true`;
   connect/set `readOnlyHint:false,destructiveHint:false`; delete/expire/logout/policy
   `destructiveHint:true`; `idempotentHint:true` on disconnect/set.
9. **Risk-level gate.** `TAILSCALE_RISK_LEVEL=read|write|admin` (default **write**, so
   connect/disconnect work out of the box). Destructive/admin tools hidden unless `admin`. This is
   coarse subsetting; the forced-approval gate (not the risk level) is the safety backstop for the
   impactful write subset.
10. **Resource bounds.** execFile timeout+SIGKILL + maxBuffer on every CLI call; per-request
    budget + 429 backoff + token caching on every REST call.
11. **ETag concurrency on ACL.** `get_policy_file` returns HuJSON + ETag; `update_policy_file`
    **requires** the ETag as `If-Match` (a concurrent edit → 412, not a silent clobber) and echoes
    the prior policy in its result so a lockout is recoverable from the transcript.
12. **Large-result hint.** `_meta["anthropic/maxResultSizeChars"]` on the tailnet-scaled reads
    (`list_devices`, `get_policy_file`, `get_audit_log`, `get_network_flow_logs`, `list_users`) so
    a big-but-legit response stays inline.

## 7. Windows specifics

- **No elevation** for up/down/set/get/logout (allowed pipe connection grants read+write; no
  UAC/`--operator`). The design has no elevation path for these.
- Invoke the binary via `execFile` directly (never `cmd`/`.bat`); `windowsHide:true`.
- Always `status --json` (exit 0 in every state); never branch on the plain-`status` exit code.
- **`syspolicy`**: MDM/GPO/registry policy can lock or silently revert prefs. Ship a read-only
  `tailscale_get_syspolicy` and, when a `set`/`up` change doesn't stick, point the user to it.
  (Renamed from a misleading "posture" label — this is *local* policy, **not** Tailscale device
  posture, which is a separate REST surface. See non-goals.)
- **Server launcher (not the tailscale calls):** `npx` on Windows resolves to a `.cmd`, which
  Node refuses to `execFile` without a shell → document launching the *server* via
  `node dist/index.js` or `cmd /c npx ...`. Env vars set in WSL/bash profiles are invisible to a
  cmd-launched server, so credentials must live in the Claude config `env` block (surface a hint
  in 401 errors).
- **Interactive-user assumption:** writes succeed as the caller's user; if the MCP server runs
  under a different account/service/session than the Tailscale GUI user, writes fail with
  access-denied. Detect this and return a specific remedy. `up`/`down`/`logout` are **machine-wide**
  side effects affecting all users of the host — documented.

## 8. Configuration & auth

Two independent layers, injected via the Claude config `mcpServers.tailscale.env` block:

**(1) Local host — no credential.** CLI/LocalAPI act as the server's OS user.

**(2) Tailnet REST (P2 tools only):**
- `TAILSCALE_OAUTH_CLIENT_ID` + `TAILSCALE_OAUTH_CLIENT_SECRET` — **preferred** (least-privilege,
  short-lived tokens). Half a pair is rejected at startup.
- `TAILSCALE_API_KEY` — legacy static admin key (inherits creator's full role).
- `TAILSCALE_TAILNET` — default `-` (the credential's own tailnet). **Startup cross-check:** warn
  if this differs from the local node's `CurrentTailnet` (`tail6073a5.ts.net`) — closes the
  "silently acting on the wrong tailnet" footgun.
- `TAILSCALE_API_BASE_URL` — default `https://api.tailscale.com` (https/loopback only).

**Other env:** `TAILSCALE_CLI_PATH`, `TS_LOCAL_API` (0/1), `TAILSCALE_RISK_LEVEL`
(read/write/admin, default write), `TAILSCALE_AUTH_KEY_FILE` (headless first-login; passed as
`file:<path>`).

**OAuth scopes by tier (documented):** read-only = `all:read`; device mgmt = `devices:core`
(+ tags); routes = `devices:routes`; dns = `dns`; policy = `policy_file`; keys = `auth_keys`.
`create_auth_key` / `update_policy_file` are tailnet-admin-equivalent. `server_info` surfaces the
token's *actual* granted scopes so an over-privileged credential is visible.

## 9. Tool inventory

Legend: **🔒** = forced-approval (`requiresUserInteraction`); **📈** = large-result hint; kind =
read / write / destructive.

### P0 — core (ships first; CLI-only, credential-free, proves the must-work requirement)
| Tool | Kind | Notes |
|---|---|---|
| `tailscale_status` | read | normalized state incl. daemon-unreachable & key-expiry; emits backendState+selfOnline |
| `tailscale_get_prefs` | read | `get --json` (works while Stopped) |
| `tailscale_connect` | write | bare `up`; expired-key→AuthURL; verify via `wait`+online-poll. Connectivity-only |
| `tailscale_disconnect` | write **🔒** | `down`; bounded poll to Stopped; reversible |

### P1 — local host management
`set_prefs` (write; benign prefs only), `set_exit_node` (write **🔒**), `set_routes`
advertise/accept (write **🔒**), `list_exit_nodes` (read), `ping` (read), `netcheck` (read),
`version` (read), `whois` (read), `whoami` (read), `dns_status` (read), `get_syspolicy` (read),
`switch_profile` (write **🔒**), `logout` (destructive **🔒**, admin), `server_info` (meta/read,
capabilities catalog: for a tool name, reports exists / risk-gated / needs-creds).
*Under consideration for P1:* `serve`/`funnel` (local CLI, no elevation — a differentiator;
`funnel` admin-gated for public exposure) — see open decisions.

### P2 — tailnet REST (enumerated as verb×noun, not endpoint files)
- **Devices:** `list_devices` 📈, `get_device`, `authorize_device` (write), `deauthorize_device`
  (write), `expire_device_key` (destructive 🔒), `delete_device` (destructive 🔒), `set_device_name`
  (write), `set_device_tags` (write), `get_device_routes` (read), `set_device_routes` (write),
  `set_device_ip` (write), `update_device_key` (write).
- **DNS:** `get_dns_nameservers`/`set_dns_nameservers`, `get_dns_preferences`/`set` (MagicDNS),
  `get_dns_searchpaths`/`set`, split-DNS (full-replace + partial-merge).
- **Policy (ACL):** `get_policy_file` (read 📈, +ETag), `validate_policy_file` (read),
  `preview_policy_file` (read), `update_policy_file` (destructive 🔒, requires If-Match ETag),
  `diff_acl_access` (read 📈 — who gains/loses access; strong pre-write guardrail).
- **Keys:** `list_auth_keys`, `get_auth_key`, `create_auth_key` (write, secret-returning),
  `delete_auth_key` (destructive 🔒). OAuth-client lifecycle (list/create/delete) — decide.
- **Settings:** `get_tailnet_settings`, `update_tailnet_settings` (write).
- **Webhooks:** `list_webhooks`, `create_webhook` (write), `delete_webhook` (destructive 🔒).
- **Users:** `list_users` 📈, `get_user`, `approve_user` (write), `suspend_user`/`restore_user`
  (write, reversible), `update_user_role` (write, admin), `delete_user` (destructive 🔒, admin).
- **Observability (read-only, high value / low risk):** `get_audit_log` 📈,
  `get_network_flow_logs` 📈.

### MCP Resources & Prompts (ergonomics; both reference repos ship these)
- Resources: `tailnet://status`, `tailnet://devices`, `device://{id}`, `acl://current`.
- Prompts: `diagnose_connectivity`, `review_acl_change` (ported from HexSleeves).

## 10. Explicit non-goals for v1 (named cuts, not silent omissions)

- **Tailnet lock (TKA)** — high-risk, easy to brick access. Excluded.
- **Taildrop / Taildrive / `tailscale file` / `cert`** — niche; excluded.
- **`tailscale update`** (client self-update) — mutates the installed Windows service / triggers
  the installer. Excluded (or admin-gated with `--dry-run` default if ever added).
- **Log-streaming config** (Axiom/Datadog/Splunk/S3 SIEM shipping) — enterprise; excluded.
- **Multi-tailnet / org-tailnet create/list/delete** — single-tailnet for v1 (with the startup
  cross-check warning).
- **Device posture *API*** (integrations + posture attributes) — deferred; **named here so it's
  not confused** with the local `get_syspolicy` tool.
- **Device/user invites, Tailscale Services** — deferred to a later P2 sub-phase; listed so scope
  is visible.

## 11. Adversarial fine-tuning — what the critiques changed

The three critics ran against our draft and the two reference repos. Net verdict: our **P0 is
stronger than either reference** (set-then-bare-`up` fixes a bug HexSleeves has by putting flags on
`up`; host connect/disconnect is a capability YawLabs *deliberately refuses* — our verified "no
elevation on Windows" finding makes it viable). Changes we adopted:

- **`confirm:true` → client-enforced `requiresUserInteraction`** on a narrow high-impact set (the
  single biggest security fix; `confirm` alone is no gate against an autonomous/injected model).
- **Traffic-redirection tools (exit-node/routes/switch) special-cased** to forced-approval
  regardless of risk level; results surface the target node.
- **Interactive-login no longer hangs** — poll `status --json` for `AuthURL` instead of reading a
  blocking `up --json` under buffered execFile.
- **Expired node key routed to the auth path**, not bare `up` (was a guaranteed-eventually hang).
- **One definition of "connected"** — `wait` + online-poll; emit both `backendState` & `selfOnline`.
- **`daemon_unreachable` is a first-class status**; full host-path error taxonomy
  (`{code, message, remedy}`): not-installed / daemon-off / needs-login / permission-denied /
  syspolicy-locked / timeout.
- **Flag-smuggling closed** — single `--flag=value` tokens, reject `-`-leading values, no `raw()`
  tool, with a test.
- **ACL writes get ETag/If-Match** + prior-policy echo; added `diff_acl_access`.
- **Redaction by exact-value match** across all model-facing output, form-encoded secrets included.
- **Coverage cuts made explicit** (§10); **"posture" conflation fixed** (renamed to
  `get_syspolicy`); added **users**, **audit/flow logs**, **MCP resources/prompts**, and a
  **capabilities catalog** in `server_info` so the agent can tell "not built" from "gated off"
  from "no creds".
- **`maxResultSizeChars`** on tailnet-scaled reads.

## 12. Open decisions (recommendations in **bold**)

1. **REST auth default:** standardize on **OAuth client-credentials**, treat `TAILSCALE_API_KEY`
   as legacy fallback. (Also: do you want to wire up REST creds at all soon, or is P0/P1 host
   control the near-term focus?)
2. **Risk-level default:** keep **`write`** (connect/disconnect work out of the box; impactful
   subset still forced-approval), vs. `read` requiring an explicit opt-in for any write.
3. **`serve`/`funnel`:** include in **P1** (local, no elevation; `funnel` admin-gated) or defer?
4. **First-login UX:** support **both** — always surface the interactive AuthURL *and* allow a
   headless `TAILSCALE_AUTH_KEY_FILE`.
5. **LocalAPI fast path:** **defer to Phase 3** (CLI is sufficient); build now only if you want
   sub-ms status.
6. **Distribution:** **`node dist/index.js`** for v1 (+ `cmd /c npx` docs), later an `.mcpb`
   bundle.
7. **License / CI:** repo is MIT in `package.json`; add a `LICENSE` file? CI is optional (recall
   the `workflow` token-scope caveat).

## 13. Phasing

- **Phase 0 (now):** scaffold ✔, config, redacting logger, binary-resolver, CliExecutor +
  argv-allowlist, status-parse, host-only TailscaleService, and the **4 P0 tools**. Acceptance:
  on this host, Claude connects (`Stopped→Running`, verified) and disconnects (`→Stopped`) with no
  elevation, no creds.
- **Phase 1:** remaining CLI/host tools + risk gating + forced-approval wiring + `server_info`
  catalog.
- **Phase 2:** `TailscaleApiClient` (auth cache, base-pin, 429/budget) + REST tool groups +
  facade fallbacks + resources/prompts.
- **Phase 3:** optional LocalAPI named-pipe adapter; `.mcpb` packaging + install docs; test suite
  (argv-allowlist, redaction, status-parse, connect state machine); 429/budget tuning.

## 14. How we differ from the reference servers

| Dimension | HexSleeves | YawLabs | **Ours** |
|---|---|---|---|
| Host connect/disconnect | partial (flags on `up`, admin-gated) | **refuses** ("needs elevation") | **yes** — verified no-elevation on Windows, set-then-bare-`up` |
| Human-approval gate | none (relies on annotations) | `requiresUserInteraction` (REST only) | `requiresUserInteraction` on **host + REST** high-impact set |
| Argv hardening | 2-token flags | N/A (no host writes) | single `--flag=value`, `-`-reject, allow-list chokepoint, no `raw()` |
| Connect success detection | — | — | `wait` + online-poll, one definition, daemon-unreachable state |
| REST breadth | ~18 tools | ~97 tools | focused P2 (devices/dns/acl/keys/settings/webhooks/users/logs) + explicit cuts |
| Transport | stdio + HTTP | stdio (+ SEA binary) | stdio (v1) |

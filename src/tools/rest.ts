/**
 * P2 tailnet REST tools. Registered only when API credentials are configured
 * (see tools/index.ts), then further gated by risk level:
 *   read  — list/get devices, routes, dns, policy(get/validate), keys(list),
 *           settings(get), webhooks(list), users(list/get), audit log
 *   write — authorize/name/tags/routes device, dns set, webhook create,
 *           user approve/suspend/restore
 *   admin — expire/delete device (🔒), policy update (🔒, If-Match), key
 *           create / delete (🔒), settings update, webhook delete (🔒)
 * 🔒 = forced-approval via _meta.
 */
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Config, RiskLevel } from "../config.js";
import { TailscaleApiClient, ApiError } from "../backends/api/client.js";
import { buildToolMeta } from "../meta/approval.js";
import { allows } from "../meta/risk.js";
import { cidrArraySchema, deviceIdSchema, tagSchema } from "../validation/schemas.js";
import { fail, jsonResult, textResult } from "./_shared.js";
import { redact } from "../util/redact.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

function restFail(e: unknown): CallToolResult {
  if (e instanceof ApiError) return { isError: true, content: [{ type: "text", text: redact(e.toText()) }] };
  return fail(e);
}

export function registerRestTools(server: McpServer, api: TailscaleApiClient, config: Config): void {
  const risk: RiskLevel = config.riskLevel;
  const enc = encodeURIComponent;
  const device = (id: string): string => `/api/v2/device/${enc(id)}`;

  // ============================ READ ============================
  if (allows(risk, "read")) {
    server.registerTool(
      "tailscale_list_devices",
      {
        title: "List tailnet devices",
        description:
          "List all devices in the tailnet (GET /tailnet/{t}/devices). `fields=all` includes extended fields. " +
          "Returns the device array; resolve a device's stable numeric `id` here for other device tools. Read-only.",
        inputSchema: { fields: z.enum(["default", "all"]).default("default").describe("Field set to return.") },
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_list_devices"),
      },
      async ({ fields }) => {
        try {
          const res = await api.get(api.tnet("/devices"), { fields });
          return jsonResult(res.data);
        } catch (e) {
          return restFail(e);
        }
      },
    );

    server.registerTool(
      "tailscale_get_device",
      {
        title: "Get a device",
        description: "Get one device by its stable numeric id (GET /device/{id}). Read-only.",
        inputSchema: { deviceId: deviceIdSchema, fields: z.enum(["default", "all"]).default("all") },
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_get_device"),
      },
      async ({ deviceId, fields }) => {
        try {
          const res = await api.get(device(deviceId), { fields });
          return jsonResult(res.data);
        } catch (e) {
          return restFail(e);
        }
      },
    );

    server.registerTool(
      "tailscale_get_device_routes",
      {
        title: "Get device routes",
        description: "List a device's advertised vs enabled subnet routes (GET /device/{id}/routes). Read-only.",
        inputSchema: { deviceId: deviceIdSchema },
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_get_device_routes"),
      },
      async ({ deviceId }) => {
        try {
          const res = await api.get(`${device(deviceId)}/routes`);
          return jsonResult(res.data);
        } catch (e) {
          return restFail(e);
        }
      },
    );

    server.registerTool(
      "tailscale_get_dns_config",
      {
        title: "Get DNS configuration",
        description:
          "Get part of the tailnet DNS config: nameservers | preferences (MagicDNS) | searchpaths | splitdns | configuration. Read-only.",
        inputSchema: {
          section: z.enum(["nameservers", "preferences", "searchpaths", "splitdns", "configuration"]),
        },
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_get_dns_config"),
      },
      async ({ section }) => {
        try {
          const path = section === "splitdns" ? "/dns/split-dns" : `/dns/${section}`;
          const res = await api.get(api.tnet(path));
          return jsonResult(res.data);
        } catch (e) {
          return restFail(e);
        }
      },
    );

    server.registerTool(
      "tailscale_get_policy_file",
      {
        title: "Get ACL policy file",
        description:
          "Get the tailnet ACL policy as raw HuJSON (comments preserved) plus its ETag (GET /tailnet/{t}/acl). " +
          "COPY THE ETag — tailscale_update_policy_file requires it as If-Match so a concurrent edit can't be " +
          "silently overwritten. Read-only.",
        inputSchema: {},
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_get_policy_file"),
      },
      async () => {
        try {
          const res = await api.get<string>(api.tnet("/acl"), undefined, { accept: "application/hujson", parse: "text" });
          const etag = res.etag ?? "(none)";
          return textResult(`ETag: ${etag}\n(Use this ETag as ifMatch when updating.)\n\n${res.data}`);
        } catch (e) {
          return restFail(e);
        }
      },
    );

    server.registerTool(
      "tailscale_validate_policy_file",
      {
        title: "Validate an ACL policy",
        description:
          "Validate a candidate ACL policy (HuJSON) and run its ACL tests WITHOUT applying it (POST /acl/validate). " +
          "Returns validation errors or an empty result if valid. Read-only / non-destructive.",
        inputSchema: { policy: z.string().min(2).max(500_000).describe("Candidate policy as HuJSON/JSON text.") },
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_validate_policy_file"),
      },
      async ({ policy }) => {
        try {
          const res = await api.post(api.tnet("/acl/validate"), policy, { hujson: true });
          return jsonResult(res.data ?? { ok: true });
        } catch (e) {
          return restFail(e);
        }
      },
    );

    server.registerTool(
      "tailscale_list_auth_keys",
      {
        title: "List auth keys",
        description:
          "List auth keys for the tailnet (GET /tailnet/{t}/keys). Set includeAll to also include OAuth clients / API " +
          "tokens. Secrets are never returned by list/get. Read-only.",
        inputSchema: { includeAll: z.boolean().default(false).describe("Include OAuth clients and API access tokens.") },
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_list_auth_keys"),
      },
      async ({ includeAll }) => {
        try {
          const res = await api.get(api.tnet("/keys"), includeAll ? { all: "true" } : undefined);
          return jsonResult(res.data);
        } catch (e) {
          return restFail(e);
        }
      },
    );

    server.registerTool(
      "tailscale_get_tailnet_settings",
      {
        title: "Get tailnet settings",
        description: "Get tailnet-wide settings (device approval, key expiry, network-flow logging, etc.) (GET /tailnet/{t}/settings). Read-only.",
        inputSchema: {},
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_get_tailnet_settings"),
      },
      async () => {
        try {
          const res = await api.get(api.tnet("/settings"));
          return jsonResult(res.data);
        } catch (e) {
          return restFail(e);
        }
      },
    );

    server.registerTool(
      "tailscale_list_webhooks",
      {
        title: "List webhooks",
        description: "List webhook endpoints for the tailnet (GET /tailnet/{t}/webhooks). Read-only.",
        inputSchema: {},
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_list_webhooks"),
      },
      async () => {
        try {
          const res = await api.get(api.tnet("/webhooks"));
          return jsonResult(res.data);
        } catch (e) {
          return restFail(e);
        }
      },
    );

    server.registerTool(
      "tailscale_list_users",
      {
        title: "List users",
        description: "List tailnet users, optionally filtered by type (member|shared) or role (GET /tailnet/{t}/users). Read-only.",
        inputSchema: {
          type: z.enum(["member", "shared", "all"]).default("all"),
          role: z.string().max(32).optional().describe("Filter by role, e.g. admin, member, owner."),
        },
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_list_users"),
      },
      async ({ type, role }) => {
        try {
          const query: Record<string, string> = {};
          if (type !== "all") query.type = type;
          if (role) query.role = role;
          const res = await api.get(api.tnet("/users"), query);
          return jsonResult(res.data);
        } catch (e) {
          return restFail(e);
        }
      },
    );

    server.registerTool(
      "tailscale_get_user",
      {
        title: "Get a user",
        description: "Get one user by id (GET /users/{id}). Read-only.",
        inputSchema: { userId: z.string().min(1).max(128) },
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_get_user"),
      },
      async ({ userId }) => {
        try {
          const res = await api.get(`/api/v2/users/${enc(userId)}`);
          return jsonResult(res.data);
        } catch (e) {
          return restFail(e);
        }
      },
    );

    server.registerTool(
      "tailscale_get_audit_log",
      {
        title: "Get audit (configuration) log",
        description:
          "Read the tailnet audit/configuration log — who changed what, when — over a bounded time window " +
          "(GET /tailnet/{t}/logging/configuration?start&end). start and end are RFC3339 timestamps and are required. Read-only.",
        inputSchema: {
          start: z.string().min(4).describe("RFC3339 start time, e.g. 2026-09-01T00:00:00Z."),
          end: z.string().min(4).describe("RFC3339 end time, e.g. 2026-09-11T00:00:00Z."),
        },
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: true },
        _meta: buildToolMeta("tailscale_get_audit_log"),
      },
      async ({ start, end }) => {
        try {
          const res = await api.get(api.tnet("/logging/configuration"), { start, end });
          return jsonResult(res.data);
        } catch (e) {
          return restFail(e);
        }
      },
    );
  }

  // ============================ WRITE ============================
  if (allows(risk, "write")) {
    server.registerTool(
      "tailscale_authorize_device",
      {
        title: "Authorize / deauthorize a device",
        description: "Set a device's authorized flag (POST /device/{id}/authorized). Read-write.",
        inputSchema: { deviceId: deviceIdSchema, authorized: z.boolean() },
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_authorize_device"),
      },
      async ({ deviceId, authorized }) => {
        try {
          await api.post(`${device(deviceId)}/authorized`, { authorized });
          return textResult(`Device ${deviceId} authorized=${authorized}.`);
        } catch (e) {
          return restFail(e);
        }
      },
    );

    server.registerTool(
      "tailscale_set_device_name",
      {
        title: "Set device name",
        description: "Set a device's (DNS) name (POST /device/{id}/name). Read-write.",
        inputSchema: { deviceId: deviceIdSchema, name: z.string().min(1).max(253) },
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_set_device_name"),
      },
      async ({ deviceId, name }) => {
        try {
          await api.post(`${device(deviceId)}/name`, { name });
          return textResult(`Device ${deviceId} name set to "${name}".`);
        } catch (e) {
          return restFail(e);
        }
      },
    );

    server.registerTool(
      "tailscale_set_device_tags",
      {
        title: "Set device tags",
        description:
          "Replace a device's ACL tags (POST /device/{id}/tags). This REPLACES all tags — pass the full desired set. " +
          "You must own the tags (ACL tagOwners). Read-write.",
        inputSchema: { deviceId: deviceIdSchema, tags: z.array(tagSchema).max(64).describe('Full tag set, e.g. ["tag:server"].') },
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_set_device_tags"),
      },
      async ({ deviceId, tags }) => {
        try {
          await api.post(`${device(deviceId)}/tags`, { tags });
          return textResult(`Device ${deviceId} tags set to: ${tags.join(", ") || "(none)"}.`);
        } catch (e) {
          return restFail(e);
        }
      },
    );

    server.registerTool(
      "tailscale_set_device_routes",
      {
        title: "Set device enabled routes",
        description:
          "Set the ENABLED subnet routes for a device (POST /device/{id}/routes). This REPLACES the full enabled set " +
          "(send the complete list). The device must already advertise a route for it to be enabled; enabling " +
          "0.0.0.0/0 + ::/0 approves it as an exit node. Read-write.",
        inputSchema: { deviceId: deviceIdSchema, routes: cidrArraySchema.describe("Full set of CIDRs to enable; [] disables all.") },
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_set_device_routes"),
      },
      async ({ deviceId, routes }) => {
        try {
          const res = await api.post(`${device(deviceId)}/routes`, { routes });
          return jsonResult(res.data ?? { enabledRoutes: routes });
        } catch (e) {
          return restFail(e);
        }
      },
    );

    server.registerTool(
      "tailscale_set_dns_config",
      {
        title: "Set DNS configuration",
        description:
          "Set part of the tailnet DNS config. section=nameservers (dns[]), preferences (magicDNS bool; needs a " +
          "nameserver set first), searchpaths (searchPaths[]), or splitdns (splitDns map; mode=merge PATCHes/removes " +
          "with null, mode=replace PUTs the whole map). Read-write.",
        inputSchema: {
          section: z.enum(["nameservers", "preferences", "searchpaths", "splitdns"]),
          nameservers: z.array(z.string()).max(64).optional(),
          magicDNS: z.boolean().optional(),
          searchPaths: z.array(z.string()).max(64).optional(),
          splitDns: z.record(z.string(), z.union([z.array(z.string()), z.null()])).optional(),
          splitDnsMode: z.enum(["merge", "replace"]).default("merge"),
        },
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_set_dns_config"),
      },
      async ({ section, nameservers, magicDNS, searchPaths, splitDns, splitDnsMode }) => {
        try {
          if (section === "nameservers") {
            if (!nameservers) throw new ApiError(0, "Provide `nameservers` for section=nameservers.");
            await api.post(api.tnet("/dns/nameservers"), { dns: nameservers });
            return textResult(`Nameservers set to: ${nameservers.join(", ")}.`);
          }
          if (section === "preferences") {
            if (magicDNS === undefined) throw new ApiError(0, "Provide `magicDNS` for section=preferences.");
            await api.post(api.tnet("/dns/preferences"), { magicDNS });
            return textResult(`MagicDNS set to ${magicDNS}.`);
          }
          if (section === "searchpaths") {
            if (!searchPaths) throw new ApiError(0, "Provide `searchPaths` for section=searchpaths.");
            await api.post(api.tnet("/dns/searchpaths"), { searchPaths });
            return textResult(`Search paths set to: ${searchPaths.join(", ")}.`);
          }
          // splitdns
          if (!splitDns) throw new ApiError(0, "Provide `splitDns` for section=splitdns.");
          const res =
            splitDnsMode === "replace"
              ? await api.put(api.tnet("/dns/split-dns"), splitDns)
              : await api.patch(api.tnet("/dns/split-dns"), splitDns);
          return jsonResult(res.data ?? { ok: true, mode: splitDnsMode });
        } catch (e) {
          return restFail(e);
        }
      },
    );

    server.registerTool(
      "tailscale_create_webhook",
      {
        title: "Create a webhook",
        description:
          "Create a webhook endpoint (POST /tailnet/{t}/webhooks). providerType is one of '', slack, mattermost, " +
          "googlechat, discord. subscriptions are event-type enums (e.g. nodeCreated, userApproved, policyUpdate). " +
          "The signing secret is returned only once. Read-write.",
        inputSchema: {
          endpointUrl: z.string().url().max(2048),
          providerType: z.enum(["", "slack", "mattermost", "googlechat", "discord"]).default(""),
          subscriptions: z.array(z.string().max(64)).min(1).max(64),
        },
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
        _meta: buildToolMeta("tailscale_create_webhook"),
      },
      async ({ endpointUrl, providerType, subscriptions }) => {
        try {
          const res = await api.post(api.tnet("/webhooks"), { endpointUrl, providerType, subscriptions });
          return jsonResult(res.data);
        } catch (e) {
          return restFail(e);
        }
      },
    );

    for (const op of ["approve", "suspend", "restore"] as const) {
      server.registerTool(
        `tailscale_${op}_user`,
        {
          title: `${op[0]!.toUpperCase()}${op.slice(1)} a user`,
          description:
            op === "approve"
              ? "Approve a pending user (POST /users/{id}/approve). Read-write."
              : op === "suspend"
                ? "Suspend a user (POST /users/{id}/suspend). Reversible with tailscale_restore_user. Read-write."
                : "Restore a suspended user (POST /users/{id}/restore). Read-write.",
          inputSchema: { userId: z.string().min(1).max(128) },
          annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
          _meta: buildToolMeta(`tailscale_${op}_user`),
        },
        async ({ userId }) => {
          try {
            await api.post(`/api/v2/users/${enc(userId)}/${op}`);
            return textResult(`User ${userId}: ${op} succeeded.`);
          } catch (e) {
            return restFail(e);
          }
        },
      );
    }
  }

  // ============================ ADMIN ============================
  if (allows(risk, "admin")) {
    server.registerTool(
      "tailscale_expire_device_key",
      {
        title: "Expire a device's key",
        description:
          "Expire a device's node key (POST /device/{id}/expire), forcing it to re-authenticate. Reversible (the device " +
          "can log in again) but disruptive. Requires user approval. Admin.",
        inputSchema: { deviceId: deviceIdSchema },
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_expire_device_key"),
      },
      async ({ deviceId }) => {
        try {
          await api.post(`${device(deviceId)}/expire`);
          return textResult(`Device ${deviceId} key expired; it must re-authenticate.`);
        } catch (e) {
          return restFail(e);
        }
      },
    );

    server.registerTool(
      "tailscale_delete_device",
      {
        title: "Delete a device",
        description:
          "Permanently remove a device from the tailnet (DELETE /device/{id}). Irreversible. Requires user approval. Admin.",
        inputSchema: { deviceId: deviceIdSchema },
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_delete_device"),
      },
      async ({ deviceId }) => {
        try {
          await api.del(device(deviceId));
          return textResult(`Device ${deviceId} permanently deleted from the tailnet.`);
        } catch (e) {
          return restFail(e);
        }
      },
    );

    server.registerTool(
      "tailscale_update_policy_file",
      {
        title: "Update ACL policy file",
        description:
          "Replace the tailnet ACL policy (POST /tailnet/{t}/acl). ⚠ A bad policy can lock every device out of the " +
          "tailnet. REQUIRES `ifMatch` — the ETag from tailscale_get_policy_file — so a concurrent edit yields 412 " +
          "instead of a silent overwrite. Validate first with tailscale_validate_policy_file. Requires user approval. Admin.",
        inputSchema: {
          policy: z.string().min(2).max(500_000).describe("New policy as HuJSON/JSON text."),
          ifMatch: z.string().min(1).describe('ETag from tailscale_get_policy_file, or "ts-default".'),
        },
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
        _meta: buildToolMeta("tailscale_update_policy_file"),
      },
      async ({ policy, ifMatch }) => {
        try {
          const res = await api.post(api.tnet("/acl"), policy, { hujson: true, ifMatch });
          return jsonResult(res.data ?? { ok: true });
        } catch (e) {
          return restFail(e);
        }
      },
    );

    server.registerTool(
      "tailscale_create_auth_key",
      {
        title: "Create an auth key",
        description:
          "Create a tailnet auth key (POST /tailnet/{t}/keys) for enrolling nodes. The plaintext key is returned ONCE " +
          "in the result — capture it. Creating a key with tags requires you to own those tags. Admin.",
        inputSchema: {
          reusable: z.boolean().default(false),
          ephemeral: z.boolean().default(false),
          preauthorized: z.boolean().default(false),
          tags: z.array(tagSchema).max(64).default([]),
          expirySeconds: z.number().int().min(0).max(7776000).optional().describe("Key lifetime in seconds (max 90 days)."),
          description: z.string().max(200).optional(),
        },
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
        _meta: buildToolMeta("tailscale_create_auth_key"),
      },
      async ({ reusable, ephemeral, preauthorized, tags, expirySeconds, description }) => {
        try {
          const body: Record<string, unknown> = {
            capabilities: { devices: { create: { reusable, ephemeral, preauthorized, tags } } },
          };
          if (expirySeconds !== undefined) body.expirySeconds = expirySeconds;
          if (description !== undefined) body.description = description;
          const res = await api.post(api.tnet("/keys"), body);
          // The result contains the one-time secret; return it to the user but do not log it.
          return jsonResult(res.data);
        } catch (e) {
          return restFail(e);
        }
      },
    );

    server.registerTool(
      "tailscale_delete_auth_key",
      {
        title: "Delete an auth key",
        description: "Revoke/delete an auth key immediately (DELETE /tailnet/{t}/keys/{id}). Irreversible. Requires user approval. Admin.",
        inputSchema: { keyId: z.string().min(1).max(128) },
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_delete_auth_key"),
      },
      async ({ keyId }) => {
        try {
          await api.del(api.tnet(`/keys/${enc(keyId)}`));
          return textResult(`Auth key ${keyId} deleted.`);
        } catch (e) {
          return restFail(e);
        }
      },
    );

    server.registerTool(
      "tailscale_update_tailnet_settings",
      {
        title: "Update tailnet settings",
        description:
          "Partially update tailnet-wide settings (PATCH /tailnet/{t}/settings) — merge semantics. Pass only the keys to " +
          "change (e.g. devicesApprovalOn, networkFlowLoggingOn). Admin.",
        inputSchema: { values: z.record(z.string(), z.unknown()).describe("Object of setting keys to merge.") },
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_update_tailnet_settings"),
      },
      async ({ values }) => {
        try {
          const res = await api.patch(api.tnet("/settings"), values);
          return jsonResult(res.data ?? { ok: true });
        } catch (e) {
          return restFail(e);
        }
      },
    );

    server.registerTool(
      "tailscale_delete_webhook",
      {
        title: "Delete a webhook",
        description: "Delete a webhook endpoint (DELETE /webhooks/{id}). Requires user approval. Admin.",
        inputSchema: { endpointId: z.string().min(1).max(128) },
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
        _meta: buildToolMeta("tailscale_delete_webhook"),
      },
      async ({ endpointId }) => {
        try {
          await api.del(`/api/v2/webhooks/${enc(endpointId)}`);
          return textResult(`Webhook ${endpointId} deleted.`);
        } catch (e) {
          return restFail(e);
        }
      },
    );
  }
}
